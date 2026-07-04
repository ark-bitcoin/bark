
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::{deserialize, serialize};
use tokio_postgres::types::Type;

use bitcoin_ext::BlockHeight;

use crate::database::Tx;

/// Convert a [BlockHeight] into the INT4 stored in postgres.
fn height_to_sql(height: BlockHeight) -> anyhow::Result<i32> {
	i32::try_from(height).with_context(|| format!("block height {} out of range", height))
}

/// Convert an INT4 from postgres back into a [BlockHeight]. Negative
/// values can't enter through [height_to_sql], so panic on them.
fn height_from_sql(height: i32) -> BlockHeight {
	BlockHeight::try_from(height).expect("corrupt db: negative block height")
}

/// A transaction the TxNursery is following up on.
#[derive(Debug, Clone)]
pub struct NurseryTx {
	pub txid: Txid,
	pub confirm_target_height: BlockHeight,
	pub confirmed_at_height: Option<BlockHeight>,
}

impl<'t> Tx<'t> {
	/// Hand a tx over to the TxNursery.
	///
	/// Idempotent: when the tx is already in the nursery, the original
	/// target is kept.
	pub async fn upsert_nursery_tx(
		&self,
		tx: &Transaction,
		confirm_target_height: BlockHeight,
	) -> anyhow::Result<()> {
		let stmt = self.prepare_typed("
			INSERT INTO nursery_tx (txid, tx, confirm_target_height, created_at, updated_at)
			VALUES ($1, $2, $3, NOW(), NOW())
			ON CONFLICT (txid) DO NOTHING
		", &[Type::TEXT, Type::BYTEA, Type::INT4]).await?;

		self.execute(&stmt, &[
			&tx.compute_txid().to_string(), &serialize(tx),
			&height_to_sql(confirm_target_height)?,
		]).await?;

		Ok(())
	}

	/// Get the raw tx of a nursery tx.
	pub async fn get_nursery_raw_tx(&self, txid: Txid) -> anyhow::Result<Option<Transaction>> {
		let stmt = self.prepare_typed(
			"SELECT tx FROM nursery_tx WHERE txid = $1",
			&[Type::TEXT],
		).await?;

		Ok(self.query_opt(&stmt, &[&txid.to_string()]).await?.map(|row| {
			deserialize(row.get("tx")).expect("corrupt db: invalid bitcoin transaction")
		}))
	}

	/// Get all nursery txs that still need follow-up: not abandoned and
	/// not confirmed at or below `deeply_confirmed_height`, where a
	/// reorg can no longer realistically unconfirm them.
	pub async fn get_active_nursery_txs(
		&self,
		deeply_confirmed_height: BlockHeight,
	) -> anyhow::Result<Vec<NurseryTx>> {
		let stmt = self.prepare_typed("
			SELECT txid, confirm_target_height, confirmed_at_height
			FROM nursery_tx
			WHERE abandoned_at IS NULL
			AND (confirmed_at_height IS NULL OR confirmed_at_height > $1)
			ORDER BY id
		", &[Type::INT4]).await?;

		let rows = self.query(&stmt, &[&height_to_sql(deeply_confirmed_height)?]).await?;
		Ok(rows.into_iter().map(|row| {
			let txid = Txid::from_str(row.get("txid"))
				.expect("corrupt db: invalid txid");
			let confirm_target_height =
				height_from_sql(row.get("confirm_target_height"));
			let confirmed_at_height = row.get::<_, Option<i32>>("confirmed_at_height")
				.map(height_from_sql);
			NurseryTx { txid, confirm_target_height, confirmed_at_height }
		}).collect())
	}

	/// Get the txids of all unconfirmed nursery txs. Only txids, to keep
	/// the memory footprint small; fetch the (rare) tx that needs a
	/// rebroadcast with [get_nursery_raw_tx](Self::get_nursery_raw_tx).
	pub async fn get_unconfirmed_nursery_txids(&self) -> anyhow::Result<Vec<Txid>> {
		let stmt = self.prepare("
			SELECT txid FROM nursery_tx
			WHERE abandoned_at IS NULL AND confirmed_at_height IS NULL
			ORDER BY id
		").await?;

		let rows = self.query(&stmt, &[]).await?;
		Ok(rows.into_iter().map(|row| {
			Txid::from_str(row.get("txid")).expect("corrupt db: invalid txid")
		}).collect())
	}

	/// Store the confirmation height of a nursery tx.
	///
	/// Returns false when the confirmation was already recorded at this
	/// height.
	pub async fn set_nursery_tx_confirmed(
		&self,
		txid: Txid,
		confirmed_at_height: BlockHeight,
	) -> anyhow::Result<bool> {
		let stmt = self.prepare_typed("
			UPDATE nursery_tx
			SET confirmed_at_height = $2, updated_at = NOW()
			WHERE txid = $1 AND confirmed_at_height IS DISTINCT FROM $2::int4
		", &[Type::TEXT, Type::INT4]).await?;

		let rows = self.execute(&stmt, &[
			&txid.to_string(), &height_to_sql(confirmed_at_height)?,
		]).await?;

		Ok(rows > 0)
	}

	/// Clear the confirmations of all nursery txs confirmed after the
	/// given height, whose blocks a reorg evicted. Returns the txid and
	/// cleared confirmation height of each.
	pub async fn clear_nursery_confirmations_after(
		&self,
		height: BlockHeight,
	) -> anyhow::Result<Vec<(Txid, BlockHeight)>> {
		let stmt = self.prepare_typed("
			WITH reorged AS (
				SELECT id, txid, confirmed_at_height FROM nursery_tx
				WHERE confirmed_at_height > $1
			)
			UPDATE nursery_tx
			SET confirmed_at_height = NULL, updated_at = NOW()
			FROM reorged WHERE nursery_tx.id = reorged.id
			RETURNING reorged.txid, reorged.confirmed_at_height
		", &[Type::INT4]).await?;

		let rows = self.query(&stmt, &[&height_to_sql(height)?]).await?;
		Ok(rows.into_iter().map(|row| {
			let txid = Txid::from_str(row.get(0))
				.expect("corrupt db: invalid txid");
			(txid, height_from_sql(row.get(1)))
		}).collect())
	}

	/// Abandon a nursery tx: the nursery gives up on the tx and the
	/// operator won't be warned about it anymore.
	///
	/// Returns false when the txid is not in the nursery or was already
	/// abandoned.
	pub async fn abandon_nursery_tx(&self, txid: Txid) -> anyhow::Result<bool> {
		let stmt = self.prepare_typed("
			UPDATE nursery_tx SET abandoned_at = NOW(), updated_at = NOW()
			WHERE txid = $1 AND abandoned_at IS NULL
			RETURNING id
		", &[Type::TEXT]).await?;

		Ok(self.query_opt(&stmt, &[&txid.to_string()]).await?.is_some())
	}
}
