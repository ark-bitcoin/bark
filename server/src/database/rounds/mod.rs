
mod model;
use std::str::FromStr;
use std::time::Duration;

pub use model::*;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::SecretKey;
use bitcoin_ext::BlockHeight;
use tokio_postgres::types::Type;

use ark::VtxoId;
use ark::encode::ProtocolEncoding;
use ark::rounds::{RoundId, RoundSeq};
use ark::tree::signed::CachedSignedVtxoTree;

use crate::database::Db;
use crate::database::forfeits::ForfeitState;
use crate::database::query;


impl Db {
	pub async fn finish_round(
		&self,
		round_seq: RoundSeq,
		round_tx: &Transaction,
		vtxos: &CachedSignedVtxoTree,
		connector_key: &SecretKey,
		forfeit_vtxos: Vec<(VtxoId, ForfeitState)>,
	) -> anyhow::Result<()> {
		let round_txid = round_tx.compute_txid();

		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		// First, store the round itself.
		let statement = tx.prepare_typed(
			"INSERT INTO round (seq, funding_txid, funding_tx, signed_tree, nb_input_vtxos,
				connector_key, expiry, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
			RETURNING id;
			",
			&[Type::INT8, Type::TEXT, Type::BYTEA, Type::BYTEA, Type::INT4, Type::BYTEA, Type::INT4],
		).await?;
		let row = tx.query_one(
			&statement,
			&[
				&(round_seq.inner() as i64),
				&round_txid.to_string(),
				&serialize(&round_tx),
				&vtxos.spec.serialize(),
				&(forfeit_vtxos.len() as i32),
				&connector_key.secret_bytes().to_vec(),
				&(vtxos.spec.spec.expiry_height as i32)
			]
		).await?;
		let round_id = row.get::<_, i64>("id");

		// Then mark inputs as forfeited.
		let statement = tx.prepare_typed("
			UPDATE vtxo
			SET forfeit_state = $2, forfeit_round_id = $3, updated_at = NOW()
			WHERE vtxo_id = $1 AND oor_spent_txid IS NULL AND forfeit_state IS NULL;
		", &[Type::TEXT, Type::BYTEA, Type::INT8]).await?;
		for (id, forfeit_state) in forfeit_vtxos {
			let state_bytes = rmp_serde::to_vec_named(&forfeit_state)
				.expect("serde serialization");
			let rows_affected = tx.execute(&statement, &[
				&id.to_string(),
				&state_bytes,
				&round_id,
			]).await?;
			if rows_affected == 0 {
				bail!("tried to mark unspendable vtxo as forfeited: {}", id);
			}
		}

		// Finally insert new vtxos.
		query::upsert_vtxos(&tx, vtxos.all_vtxos()).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn is_round_tx(&self, txid: Txid) -> anyhow::Result<bool> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("SELECT 1 FROM round WHERE funding_txid = $1 LIMIT 1;").await?;

		let rows = conn.query(&statement, &[&txid.to_string()]).await?;
		Ok(!rows.is_empty())
	}

	pub async fn get_round(&self, id: RoundId) -> anyhow::Result<Option<StoredRound>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT id, seq, funding_txid, funding_tx, signed_tree, nb_input_vtxos, connector_key,
				expiry, swept_at, created_at
			FROM round
			WHERE funding_txid = $1;
		").await?;

		let rows = conn.query(&statement, &[&id.to_string()]).await?;
		let round = match rows.get(0) {
			Some(row) => Some(StoredRound::try_from(row.clone()).expect("corrupt db")),
			_ => None
		};

		Ok(round)
	}

	pub async fn mark_round_swept(&self, id: RoundId) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let statement = conn.prepare("
			UPDATE round SET swept_at = NOW(), updated_at = NOW() WHERE funding_txid = $1;
		").await?;

		conn.execute(&statement, &[&id.to_string()]).await?;

		Ok(())
	}

	/// Get all round IDs of rounds that expired before or on `height`
	/// and that have not been swept
	pub async fn get_expired_round_ids(&self, height: BlockHeight) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT funding_txid FROM round WHERE expiry <= $1 AND swept_at IS NULL;
		").await?;

		let rows = conn.query(&statement, &[&(height as i32)]).await?;
		Ok(rows
			.into_iter()
			.map(|row| RoundId::from_str(row.get("funding_txid")).expect("corrupt db"))
			.collect::<Vec<_>>()
		)
	}

	/// Get all new rounds since either a given round or within a lifetime window
	///
	/// Returned round ids are ordered chronologically.
	pub async fn get_fresh_round_ids(
		&self,
		last_round_id: Option<RoundId>,
		vtxo_lifetime: Option<Duration>,
	) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.get_conn().await?;

		let rows = if let Some(last) = last_round_id {
			let stmt = conn.prepare("
				SELECT funding_txid
				FROM round
				WHERE created_at > (SELECT created_at FROM round WHERE funding_txid = $1)
				ORDER BY id
			").await?;
			conn.query(&stmt, &[&last.to_string()]).await?
		} else if let Some(lifetime) = vtxo_lifetime {
			let window = lifetime + lifetime / 2;
			let stmt = conn.prepare("
				SELECT funding_txid
				FROM round
				WHERE created_at >= NOW() - ($1 * interval '1 second')
				ORDER BY id
			").await?;
			conn.query(&stmt, &[&(window.as_secs() as f64)]).await?
		} else {
			bail!("need to provide either last_round_id or vtxo_lifetime argument");
		};

		Ok(rows
			.into_iter()
			.map(|row| RoundId::from_str(row.get("funding_txid")).expect("corrupt db"))
			.collect::<Vec<_>>()
		)
	}

	pub async fn get_last_round_id(&self) -> anyhow::Result<Option<RoundId>> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare("SELECT funding_txid FROM round ORDER BY id DESC LIMIT 1").await?;
		Ok(conn.query_opt(&stmt, &[]).await?.map(|r|
			RoundId::from_str(&r.get::<_, &str>("funding_txid")).expect("corrupt db: funding txid")
		))
	}
}
