use anyhow::Context;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use chrono::{DateTime, Utc};
use cln_rpc::listsendpays_request::ListsendpaysIndex;
use lightning_invoice::Bolt11Invoice;
use log::{trace, warn};

use crate::database::Db;
use crate::database::model::{
	LightningIndexes, LightningInvoice, LightningPaymentAttempt,
	LightningPaymentStatus,
};
use crate::error::ContextExt;


/// Identifier by which CLN nodes are stored in the database.
pub type ClnNodeId = i64;

impl Db {
	// *******************
	// * lightning state *
	// *******************

	pub async fn register_lightning_node(
		&self,
		public_key: &PublicKey,
	) -> anyhow::Result<(ClnNodeId, DateTime<Utc>)> {
		let conn = self.pool.get().await?;

		let select_stmt = conn.prepare("
			SELECT lightning_node_id, updated_at
			FROM lightning_node
			WHERE public_key = $1;
		").await?;

		let pubkey = public_key.serialize();
		let rows = conn.query(&select_stmt, &[&&pubkey[..]]).await?;
		if let Some(row) = rows.get(0) {
			let id = row.get("lightning_node_id");
			let updated_at = row.get("updated_at");
			return Ok((id, updated_at));
		}

		let insert_stmt = conn.prepare("
			INSERT INTO lightning_node (
				public_key,
				payment_created_index,
				payment_updated_index,
				created_at,
				updated_at
			) VALUES ($1, 0, 0, NOW(), NOW())
			RETURNING lightning_node_id, updated_at;
		").await?;

		let rows = conn.query(&insert_stmt, &[&&pubkey[..]]).await?;
		if let Some(row) = rows.get(0) {
			let id = row.get("lightning_node_id");
			let updated_at = row.get("updated_at");

			return Ok((id, updated_at));
		}

		bail!("Failed to insert new lightning node")
	}

	// No optimistic locking possible for payment index updates because
	// each index is handled by a separate never ending thread
	pub async fn get_lightning_payment_indexes(
		&self,
		node_id: ClnNodeId,
	) -> anyhow::Result<Option<LightningIndexes>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT payment_created_index, payment_updated_index
			FROM lightning_node
			WHERE lightning_node_id = $1;
		").await?;
		let rows = conn.query(&statement, &[&node_id]).await?;

		if let Some(row) = rows.get(0) {
			let created_index = row.get::<_, i64>("payment_created_index");
			let updated_index = row.get::<_, i64>("payment_updated_index");

			let created_index = u64::try_from(created_index)
				.expect("Negative payment_created_index from DB");
			let updated_index = u64::try_from(updated_index)
				.expect("Negative payment_updated_index from DB");

			Ok(Some(LightningIndexes { created_index, updated_index }))
		} else {
			Ok(None)
		}
	}

	// No optimistic locking possible for payment index updates because
	// each index is handled by a separate never ending thread
	pub async fn store_lightning_payment_index(
		&self,
		node_id: ClnNodeId,
		kind: ListsendpaysIndex,
		index: u64,
	) -> anyhow::Result<DateTime<Utc>> {
		let conn = self.pool.get().await?;
		let statement = match kind {
			ListsendpaysIndex::Created => conn.prepare("
				UPDATE lightning_node
				SET payment_created_index=$2, updated_at=NOW()
				WHERE lightning_node_id = $1
				RETURNING updated_at;
			").await?,
			ListsendpaysIndex::Updated => conn.prepare("
				UPDATE lightning_node
				SET payment_updated_index=$2, updated_at=NOW()
				WHERE lightning_node_id = $1
				RETURNING updated_at;
			").await?,
		};

		let row = conn.query_one(&statement, &[&node_id, &(index as i64)]).await?;
		Ok(row.get("updated_at"))
	}

	pub async fn get_open_lightning_payment_attempts(
		&self,
		node_id: ClnNodeId,
	) -> anyhow::Result<Vec<LightningPaymentAttempt>> {
		let conn = self.pool.get().await?;

		let stmt = conn.prepare("
			SELECT lightning_payment_attempt_id,
				lightning_invoice_id, lightning_node_id, amount_msat, status, error,
				created_at, updated_at
			FROM lightning_payment_attempt
			WHERE status != $1 AND status != $2 AND lightning_node_id = $3
			ORDER BY created_at DESC;
		").await?;

		let status_failed = LightningPaymentStatus::Failed;
		let status_succeeded = LightningPaymentStatus::Succeeded;
		let rows = conn.query(
			&stmt, &[&status_failed, &status_succeeded, &node_id]
		).await?;

		Ok(rows.iter().map(Into::into).collect::<Vec<_>>())
	}

	pub async fn get_open_lightning_payment_attempt_by_payment_hash(
		&self,
		payment_hash: &sha256::Hash,
	) -> anyhow::Result<Option<LightningPaymentAttempt>> {
		let conn = self.pool.get().await?;

		let stmt = conn.prepare("
			SELECT attempt.lightning_payment_attempt_id,
				attempt.lightning_invoice_id, attempt.lightning_node_id, attempt.amount_msat,
				attempt.status, attempt.error, attempt.created_at, attempt.updated_at
			FROM lightning_invoice invoice
			JOIN lightning_payment_attempt attempt ON
				invoice.lightning_invoice_id = attempt.lightning_invoice_id
			WHERE invoice.payment_hash = $1 AND
				attempt.status != $2 AND attempt.status != $3
			ORDER BY attempt.created_at DESC;
		").await?;

		let status_failed = LightningPaymentStatus::Failed;
		let status_succeeded = LightningPaymentStatus::Succeeded;
		let rows = conn.query(
			&stmt, &[&&payment_hash[..], &status_failed, &status_succeeded],
		).await?;

		if rows.is_empty() {
			return Ok(None);
		}

		if rows.len() > 1 {
			warn!("Multiple open attempts for payment hash: {}", payment_hash);
		}

		if let Some(row) = rows.get(0) {
			Ok(Some(row.into()))
		} else {
			Ok(None)
		}
	}

	/// Stores data after lightning payment start.
	///
	/// If the invoice does not exist yet, it will be created
	/// and the payment attempt will be stored.
	pub async fn store_lightning_payment_start(
		&self,
		node_id: ClnNodeId,
		invoice: &Bolt11Invoice,
		amount_msat: u64,
	) -> anyhow::Result<()> {
		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		let select_stmt = tx.prepare("
			SELECT lightning_invoice_id FROM lightning_invoice WHERE payment_hash = $1
		").await?;

		let payment_hash = invoice.payment_hash();
		let existing = tx.query_opt(&select_stmt, &[&&payment_hash[..]]).await?;

		let lightning_invoice_id = if let Some(row) = existing {
			row.get("lightning_invoice_id")
		} else {
			let stmt = tx.prepare("
				INSERT INTO lightning_invoice (
					invoice,
					payment_hash,
					created_at,
					updated_at
				) VALUES ($1, $2, NOW(), NOW())
				RETURNING lightning_invoice_id;
			").await?;

			let row = tx.query_one(
				&stmt, &[&invoice.to_string(), &&payment_hash[..]],
			).await?;

			row.get("lightning_invoice_id")
		};

		self.store_lightning_payment_attempt(
			&tx, lightning_invoice_id, amount_msat, node_id,
		).await?;

		tx.commit().await?;

		Ok(())
	}

	// NB private method, we don't export lightning_invoice_id type
	async fn store_lightning_payment_attempt(
		&self,
		tx: &tokio_postgres::Transaction<'_>,
		lightning_invoice_id: i64,
		amount_msat: u64,
		node_id: ClnNodeId,
	) -> anyhow::Result<(i64, DateTime<Utc>)> {
		let requested_status = LightningPaymentStatus::Requested;

		let stmt = tx.prepare("
			INSERT INTO lightning_payment_attempt (
				lightning_invoice_id,
				lightning_node_id,
				amount_msat,
				status,
				created_at,
				updated_at
			) VALUES ($1, $2, $3, $4, NOW(), NOW())
			RETURNING lightning_payment_attempt_id, updated_at;
		").await?;

		let row = tx
			.query_one(
				&stmt,
				&[&lightning_invoice_id, &node_id, &(amount_msat as i64), &requested_status],
			).await?;

		let payment_attempt_id = row.get("lightning_payment_attempt_id");
		let updated_at = row.get("updated_at");

		trace!("Stored lightning payment attempts {} with time {:#?}.",
			payment_attempt_id,
			updated_at,
		);

		Ok((payment_attempt_id, updated_at))
	}

	pub async fn update_lightning_payment_attempt_status(
		&self,
		old_payment_attempt: &LightningPaymentAttempt,
		new_status: LightningPaymentStatus,
		new_payment_error: Option<&str>,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await.unwrap();

		// We want to preserve any previous error message in case we don't have a new one.
		if let Some(error) = new_payment_error {
			let stmt = conn.prepare("
				UPDATE lightning_payment_attempt
				SET status = $3,
					error = $4,
					updated_at = NOW()
				WHERE lightning_payment_attempt_id = $1 AND updated_at = $2
				RETURNING updated_at;
			").await?;
			conn.query_one(
				&stmt,
				&[
					&old_payment_attempt.lightning_payment_attempt_id,
					&old_payment_attempt.updated_at,
					&new_status,
					&error
				]
			).await?;
		} else {
			let stmt = conn.prepare("
				UPDATE lightning_payment_attempt
				SET status = $3,
					updated_at = NOW()
				WHERE lightning_payment_attempt_id = $1 AND updated_at = $2
				RETURNING updated_at;
			").await?;
			conn.query_one(
				&stmt,
				&[
					&old_payment_attempt.lightning_payment_attempt_id,
					&old_payment_attempt.updated_at,
					&new_status
				]
			).await?;
		};

		Ok(())
	}


	pub async fn update_lightning_invoice(
		&self,
		old_lightning_invoice: LightningInvoice,
		new_final_amount_msat: Option<u64>,
		new_preimage: Option<&[u8; 32]>,
	) -> anyhow::Result<DateTime<Utc>> {
		let conn = self.pool.get().await.unwrap();

		let stmt = conn.prepare("
			UPDATE lightning_invoice
			SET preimage = $3,
				final_amount_msat = $4,
				updated_at = NOW()
			WHERE lightning_invoice_id = $1 AND updated_at = $2
			RETURNING updated_at;
		").await?;

		let final_amount_msat = new_final_amount_msat.map(|u| u as i64);
		let row = conn.query_one(&stmt, &[
			&old_lightning_invoice.lightning_invoice_id,
			&old_lightning_invoice.updated_at,
			&new_preimage.map(|p| &p[..]),
			&final_amount_msat,
		]).await?;

		Ok(row.get("updated_at"))
	}

	pub async fn get_lightning_invoice_by_id(&self, id: i64) -> anyhow::Result<LightningInvoice> {
		let conn = self.pool.get().await?;

		let row = conn.query_one("
			SELECT DISTINCT ON (invoice.lightning_invoice_id)
				invoice.*, attempt.status
			FROM (
				SELECT *
				FROM lightning_invoice
				WHERE lightning_invoice_id = $1
			) invoice
			LEFT JOIN lightning_payment_attempt attempt
			ON invoice.lightning_invoice_id = attempt.lightning_invoice_id
			ORDER BY invoice.lightning_invoice_id, attempt.created_at DESC;",
			&[&id],
		).await.context("Failed to fetch lightning invoice by id")?;

		Ok(row.try_into()?)
	}

	pub async fn get_lightning_invoice_by_payment_hash(
		&self,
		payment_hash: &sha256::Hash,
	) -> anyhow::Result<LightningInvoice> {
		let conn = self.pool.get().await?;

		let res = conn.query_opt("
			SELECT DISTINCT ON (invoice.lightning_invoice_id)
				invoice.*, attempt.status
			FROM (
				SELECT *
				FROM lightning_invoice
				WHERE payment_hash = $1
			) invoice
			LEFT JOIN lightning_payment_attempt attempt
			ON invoice.lightning_invoice_id = attempt.lightning_invoice_id
			ORDER BY invoice.lightning_invoice_id, attempt.created_at DESC;",
			&[&&payment_hash[..]],
		).await.context("error fetching lightning invoice by payment_hash")?;
		Ok(res.not_found([payment_hash], "payment not found")?.try_into()?)
	}
}
