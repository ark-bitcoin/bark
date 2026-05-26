use std::str::FromStr;

use anyhow::Context;
use bitcoin::{consensus, Amount};
use chrono::DateTime;
use rusqlite::{Transaction, named_params};

use ark::VtxoId;

use crate::actions::WalletActionCheckpoint;
use crate::actions::offboard::{Offboard, OffboardKind, Progress};
use crate::movement::MovementId;

use super::Migration;

pub struct Migration0041 {}

impl Migration for Migration0041 {
	fn name(&self) -> &str {
		"Move pending offboards into wallet action checkpoint table"
	}

	fn to_version(&self) -> i64 { 41 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		// Read all rows from the legacy table.
		let rows: Vec<LegacyPendingOffboard> = {
			let mut stmt = conn.prepare(
				"SELECT movement_id, offboard_txid, offboard_tx, vtxo_ids, destination, created_at
				 FROM bark_pending_offboard",
			)?;
			stmt
				.query_map((), |row| {
					Ok(LegacyPendingOffboard {
						movement_id: MovementId::new(row.get::<_, u32>("movement_id")?),
						offboard_txid: row.get::<_, String>("offboard_txid")?,
						offboard_tx: row.get::<_, Vec<u8>>("offboard_tx")?,
						vtxo_ids: row.get::<_, String>("vtxo_ids")?,
						destination: row.get::<_, String>("destination")?,
						created_at: row.get::<_, DateTime<chrono::Utc>>("created_at")?,
					})
				})?
				.collect::<Result<_, _>>()?
		};

		for legacy in rows {
			let action = legacy.into_offboard()
				.context("failed to convert legacy pending offboard")?;
			let id = action.id();
			let checkpoint: WalletActionCheckpoint = action.into();
			let payload = serde_json::to_vec(&checkpoint)
				.context("failed to serialize backfilled offboard checkpoint")?;
			conn.execute(
				"INSERT OR IGNORE INTO bark_wallet_action_checkpoint (id, payload)
				 VALUES (:id, :payload)",
				named_params! {
					":id": id,
					":payload": payload,
				},
			).context("failed to insert backfilled offboard checkpoint")?;
		}

		conn.execute("DROP TABLE bark_pending_offboard", ())
			.context("failed to drop bark_pending_offboard table")?;

		Ok(())
	}
}

struct LegacyPendingOffboard {
	movement_id: MovementId,
	offboard_txid: String,
	offboard_tx: Vec<u8>,
	vtxo_ids: String,
	destination: String,
	created_at: chrono::DateTime<chrono::Utc>,
}

impl LegacyPendingOffboard {
	fn into_offboard(self) -> anyhow::Result<Offboard> {
		let offboard_txid = bitcoin::Txid::from_str(&self.offboard_txid)
			.context("invalid legacy offboard_txid")?;
		let offboard_tx: bitcoin::Transaction = consensus::deserialize(&self.offboard_tx)
			.context("invalid legacy offboard_tx")?;
		let vtxo_ids: Vec<VtxoId> = serde_json::from_str(&self.vtxo_ids)
			.context("invalid legacy vtxo_ids")?;
		let destination = bitcoin::Address::from_str(&self.destination)
			.context("invalid legacy destination address")?
			.into_unchecked();

		// `movement_id` is a stable identifier we already track for
		// pending offboards, so we reuse it as the action id. New
		// offboards will use random ids, but legacy rows keep their
		// movement-keyed names so an in-flight offboard survives the
		// upgrade without losing its checkpoint identity.
		let id = format!("legacy-mov-{}", self.movement_id.0);

		// fee_rate and kind only matter before broadcast; both are
		// irrelevant for `AwaitingConfirmations` and below. We pick placeholders
		// that round-trip cleanly via serde.
		let placeholder_net = Amount::ONE_SAT;
		let placeholder_fee = Amount::ONE_SAT;
		let placeholder_fee_rate = bitcoin::FeeRate::from_sat_per_kwu(1);
		let kind = OffboardKind::OffboardWhole { input_vtxo_ids: vtxo_ids.clone() };

		Ok(Offboard {
			id,
			destination,
			onchain_output_amount: placeholder_net,
			committed_fee: placeholder_fee,
			committed_fee_rate: placeholder_fee_rate,
			kind,
			progress: Progress::AwaitingConfirmations {
				offboard_vtxo_ids: vtxo_ids,
				offboard_txid,
				offboard_tx,
				movement_id: self.movement_id,
				created_at: self.created_at,
			},
		})
	}
}
