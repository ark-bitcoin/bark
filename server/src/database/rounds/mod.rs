
mod model;
pub use model::*;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::SecretKey;
use bitcoin_ext::BlockHeight;
use futures::TryStreamExt;
use tokio_postgres::types::Type;

use ark::VtxoId;
use ark::encode::ProtocolEncoding;
use ark::rounds::RoundId;
use ark::tree::signed::CachedSignedVtxoTree;

use crate::database::Db;
use crate::database::model::ForfeitState;


impl Db {
	pub async fn finish_round(
		&self,
		round_tx: &Transaction,
		vtxos: &CachedSignedVtxoTree,
		connector_key: &SecretKey,
		forfeit_vtxos: Vec<(VtxoId, ForfeitState)>,
	) -> anyhow::Result<()> {
		let round_id = round_tx.compute_txid();

		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		// First, store the round itself.
		let statement = tx.prepare_typed("
			INSERT INTO round (id, tx, signed_tree, nb_input_vtxos, connector_key, expiry)
			VALUES ($1, $2, $3, $4, $5, $6);
		", &[Type::TEXT, Type::BYTEA, Type::BYTEA, Type::INT4, Type::BYTEA, Type::INT4]).await?;
		tx.execute(
			&statement,
			&[
				&round_id.to_string(),
				&serialize(&round_tx),
				&vtxos.spec.serialize(),
				&(forfeit_vtxos.len() as i32),
				&connector_key.secret_bytes().to_vec(),
				&(vtxos.spec.spec.expiry_height as i32)
			]
		).await?;

		// Then mark inputs as forfeited.
		let statement = tx.prepare_typed("
			UPDATE vtxo SET forfeit_state = $2, forfeit_round_id = $3 WHERE id = $1 AND spendable = true;
		", &[Type::TEXT, Type::BYTEA, Type::TEXT]).await?;
		for (id, forfeit_state) in forfeit_vtxos {
			let state_bytes = rmp_serde::to_vec_named(&forfeit_state)
				.expect("serde serialization");
			let rows_affected = tx.execute(&statement, &[
				&id.to_string(),
				&state_bytes,
				&round_id.to_string(),
			]).await?;
			if rows_affected == 0 {
				bail!("tried to mark unspendable vtxo as forfeited: {}", id);
			}
		}

		// Finally insert new vtxos.
		Self::inner_upsert_vtxos(&tx, vtxos.all_vtxos()).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn is_round_tx(&self, txid: Txid) -> anyhow::Result<bool> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("SELECT 1 FROM round WHERE id = $1 LIMIT 1;").await?;

		let rows = conn.query(&statement, &[&txid.to_string()]).await?;
		Ok(!rows.is_empty())
	}

	pub async fn get_round(&self, id: RoundId) -> anyhow::Result<Option<StoredRound>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key, expiry
			FROM round WHERE id = $1;
		").await?;

		let rows = conn.query(&statement, &[&id.to_string()]).await?;
		let round = match rows.get(0) {
			Some(row) => Some(StoredRound::try_from(row.clone()).expect("corrupt db")),
			_ => None
		};

		Ok(round)
	}

	pub async fn remove_round(&self, id: RoundId) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;

		let statement = conn.prepare("
			UPDATE round SET deleted_at = NOW() WHERE id = $1;
		").await?;

		conn.execute(&statement, &[&id.to_string()]).await?;

		Ok(())
	}

	/// Get all round IDs of rounds that expired before or on `height`.
	pub async fn get_expired_rounds(&self, height: BlockHeight) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key, expiry
			FROM round WHERE expiry <= $1
		").await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;
		Ok(rows.map_ok(|row| StoredRound::try_from(row).expect("corrupt db").id).try_collect::<Vec<_>>().await?)
	}

	pub async fn get_fresh_round_ids(&self, height: u32) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key, expiry
			FROM round WHERE expiry > $1
		").await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;
		Ok(rows.map_ok(|row| StoredRound::try_from(row).expect("corrupt db").id).try_collect::<Vec<_>>().await?)
	}
}
