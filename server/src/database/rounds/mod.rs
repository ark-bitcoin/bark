
mod model;
pub use model::*;


use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::serialize;
use tokio_postgres::types::Type;
use tracing::{debug, info, trace};

use ark::{ServerVtxo, VtxoId, VtxoRequest};
use ark::encode::ProtocolEncoding;
use ark::rounds::{RoundId, RoundSeq};
use ark::tree::signed::{CachedSignedVtxoTree, UnlockHash, UnlockPreimage};
use bitcoin_ext::BlockHeight;

use crate::database::Db;
use crate::database::query;
use crate::round::InteractiveParticipation;


impl Db {
	pub async fn finish_round(
		&self,
		round_seq: RoundSeq,
		round_tx: &Transaction,
		input_vtxos: impl IntoIterator<Item = VtxoId>,
		output_vtxos: &CachedSignedVtxoTree,
		interactive_participations: &HashMap<UnlockHash, InteractiveParticipation>,
	) -> anyhow::Result<()> {
		let round_txid = round_tx.compute_txid();
		info!("Storing finished round with round funding txid {}", round_txid);

		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		// First, store the round itself.
		let stmt = tx.prepare_typed(
			"INSERT INTO round (seq, funding_txid, funding_tx, signed_tree, expiry, created_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			RETURNING id;",
			&[Type::INT8, Type::TEXT, Type::BYTEA, Type::BYTEA, Type::INT4],
		).await?;
		let row = tx.query_one(
			&stmt,
			&[
				&(round_seq.inner() as i64),
				&round_txid.to_string(),
				&serialize(&round_tx),
				&output_vtxos.spec.serialize(),
				&(output_vtxos.spec.spec.expiry_height as i32)
			]
		).await?;
		let round_id = row.get::<_, i64>("id");

		// mark the input vtxos as refreshed
		let stmt = tx.prepare_typed(
			"UPDATE vtxo SET spent_in_round = $2, updated_at = NOW()
			WHERE vtxo_id = $1 AND
				oor_spent_txid IS NULL AND spent_in_round IS NULL AND offboarded_in IS NULL;",
			&[Type::TEXT, Type::INT8],
		).await?;
		for vtxo_id in input_vtxos {
			let rows_affected = tx.execute(&stmt, &[&vtxo_id.to_string(), &round_id]).await?;
			if rows_affected == 0 {
				bail!("tried to mark unspendable vtxo {} as spent in round", vtxo_id);
			}
		}

		// store round participations for the interactive participants
		let remove_existing_stmt = tx.prepare_typed(
			"DELETE FROM round_participation
			WHERE id IN (
				SELECT participation_id
				FROM round_part_input
				WHERE vtxo_id = ANY($1)
			);", &[Type::TEXT_ARRAY],
		).await?;
		for (unlock_hash, part) in interactive_participations {
			// remove any existing ones, but if the round was not full,
			// this should already have happened
			let input_strings = part.inputs.iter().map(|i| i.to_string()).collect::<Vec<_>>();
			let existing = tx.execute(&remove_existing_stmt, &[&input_strings]).await?;
			if existing > 0 {
				debug!("Had to remove existing hark participation for interactive participant \
					with input ids: {:?}", part.inputs,
				);
			}

			query::store_round_participation(
				&tx,
				*unlock_hash,
				part.unlock_preimage,
				&part.inputs,
				&part.outputs,
			).await.with_context(|| format!(
				"db rejected round participation for interactive participant (unlock_hash={}) \
				with inputs {:?}", unlock_hash, part.inputs,
			))?;
		}

		// update the hark round participations, both non-interactive and interactive
		let hark_unlock_hashes = output_vtxos.spec.spec.vtxos.iter().map(|v| v.unlock_hash);
		query::set_round_id_for_participations(&tx, hark_unlock_hashes, round_txid).await?;

		// Finally insert new vtxos.
		query::upsert_vtxos(&tx, output_vtxos.output_vtxos().map(ServerVtxo::from)).await?;

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
			SELECT id, seq, funding_txid, funding_tx, signed_tree,
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

	pub async fn get_round_participation_by_unlock_hash(
		&self,
		unlock_hash: UnlockHash,
	) -> anyhow::Result<Option<StoredRoundParticipation>> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		let part_opt = tx.query_opt(
			"SELECT id, unlock_hash, unlock_preimage, round_id, created_at \
			FROM round_participation \
			WHERE unlock_hash = $1",
			&[&unlock_hash.to_string()],
		).await?;

		let part_row = match part_opt {
			Some(r) => r,
			None => return Ok(None),
		};

		Ok(Some(query::complete_round_participation(&tx, part_row).await?))
	}

	pub async fn get_all_pending_round_participations(
		&self,
	) -> anyhow::Result<Vec<StoredRoundParticipation>> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		let parts = tx.query(
			"SELECT id, unlock_hash, unlock_preimage, round_id, created_at \
			FROM round_participation \
			WHERE round_id IS NULL",
			&[],
		).await?;

		let mut ret = Vec::with_capacity(parts.len());
		for row in parts {
			ret.push(query::complete_round_participation(&tx, row).await?);
		}

		Ok(ret)
	}

	/// Try register a new hArk round participation
	///
	/// Will check that the input vtxos are spendable.
	pub async fn try_store_round_participation(
		&self,
		unlock_preimage: UnlockPreimage,
		inputs: &[VtxoId],
		outputs: impl IntoIterator<Item = &VtxoRequest>,
	) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		let unlock_hash = UnlockHash::hash(&unlock_preimage);
		trace!("Storing round participation for unlock hash {} and inputs {:?}",
			unlock_hash, inputs,
		);

		// check that all inputs are free
		for vtxo in query::get_vtxos_by_id(&tx, inputs).await? {
			if !vtxo.is_spendable() {
				return badarg!("input vtxo {} is not spendable", vtxo.vtxo_id);
			}
		}

		query::store_round_participation(
			&tx, unlock_hash, unlock_preimage, inputs, outputs,
		).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn set_forfeit_transactions(
		&self,
		unlock_hash: UnlockHash,
		vtxo_id: VtxoId,
		signed_forfeit_tx: &Transaction,
		signed_forfeit_claim_tx: &Transaction,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"UPDATE round_part_input \
			SET signed_forfeit_tx = $3, signed_forfeit_claim_tx = $4 \
			FROM round_participation \
			WHERE round_part_input.participation_id = round_participation.id \
				AND round_participation.unlock_hash = $1 \
				AND round_participation.round_id IS NOT NULL \
				AND round_part_input.vtxo_id = $2",
			&[Type::TEXT, Type::TEXT, Type::BYTEA, Type::BYTEA]
		).await?;

		let rows_affected = conn.execute(&stmt, &[
			&unlock_hash.to_string(),
			&vtxo_id.to_string(),
			&serialize(signed_forfeit_tx),
			&serialize(signed_forfeit_claim_tx),
		]).await?;

		if rows_affected == 0 {
			return badarg!("no matching round participation input found for \
				unlock_hash {} and vtxo_id {}", unlock_hash, vtxo_id,
			);
		}

		Ok(())
	}

	pub async fn remove_round_participation(
		&self,
		unlock_hash: UnlockHash,
	) -> anyhow::Result<bool> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"WITH deleted AS (
				DELETE FROM round_participation WHERE unlock_hash = $1
				RETURNING id
			),
			_ AS (
				DELETE FROM round_part_input
				WHERE participation_id IN (SELECT id FROM deleted)
			),
			_ AS (
				DELETE FROM round_part_output
				WHERE participation_id IN (SELECT id FROM deleted)
			)
			SELECT id FROM deleted",
			&[Type::TEXT]
		).await?;
		let rows_affected = conn.execute(&stmt, &[&unlock_hash.to_string()]).await?;

		Ok(rows_affected > 0)
	}
}
