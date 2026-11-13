//! Guards between expiry payout decisions and the writes that spend the
//! same VTXOs. A stored decision makes every later spend of its VTXOs fail.

use anyhow::Context;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::VtxoId;
use ark::tree::signed::{CachedSignedVtxoTree, UnlockHash};

use crate::database::Tx;
use crate::error::ExpiryPayoutRefusal;

impl Tx<'_> {
	/// Lock the VTXOs that a write spends or changes, then refuse the write
	/// if an expiry payout decided any of them. The locks last until the
	/// transaction ends. The watchman decides payouts in another process,
	/// so locks in this process cannot order a write and a decision.
	pub(crate) async fn guard_spend_changes(&self, ids: &[VtxoId]) -> anyhow::Result<()> {
		if !self.expiry_payouts() || ids.is_empty() {
			return Ok(());
		}
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		// FOR NO KEY UPDATE still lets the owner mailbox rows of new VTXOs
		// take their foreign key locks on these rows.
		self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id = ANY($1) ORDER BY vtxo_id FOR NO KEY UPDATE", &[&ids]).await?;
		if let Some(row) = self.query_opt(
			"SELECT vtxo_id FROM (SELECT vtxo_id FROM expiry_payout_vtxo WHERE vtxo_id=ANY($1) \
				UNION SELECT vtxo_id FROM expiry_payout_input WHERE vtxo_id=ANY($1)) guarded \
				ORDER BY vtxo_id LIMIT 1",
			&[&ids],
		).await? {
			return Err(ExpiryPayoutRefusal::DecidedForPayout(row.get::<_, &str>("vtxo_id").parse()?).into());
		}
		Ok(())
	}

	/// Refuse a change to a round participation that an expiry payout
	/// cancelled. A cancelled participation can never release its preimage
	/// or finish. An input of it that no payout decided stays usable.
	async fn guard_participation(&self, participation_id: i64) -> anyhow::Result<()> {
		self.query_opt("SELECT id FROM round_participation WHERE id = $1 FOR UPDATE", &[&participation_id]).await?;
		let cancelled = self.query_opt(
			"SELECT participation_id FROM expiry_cancelled_participation WHERE participation_id = $1",
			&[&participation_id],
		).await?;
		if cancelled.is_some() {
			return badarg!("round participation {} was cancelled for an expiry payout", participation_id);
		}
		Ok(())
	}

	/// Guard the inputs and the participations of a round that finishes.
	/// The VTXO locks come before the participation locks, in the order
	/// that the expiry decision takes them, so the two cannot deadlock.
	pub(crate) async fn guard_round_finish(&self, inputs: &[VtxoId], tree: &CachedSignedVtxoTree) -> anyhow::Result<()> {
		if !self.expiry_payouts() {
			return Ok(());
		}
		self.guard_spend_changes(inputs).await?;
		for hash in tree.spec.spec.vtxos.iter().map(|v| v.unlock_hash) {
			let part = self.query_opt("SELECT id FROM round_participation WHERE unlock_hash = $1",
				&[&hash.to_string()]).await?;
			if let Some(part) = part {
				self.guard_participation(part.get("id")).await?;
			}
		}
		Ok(())
	}

	/// Guard the inputs and the participation of a forfeit commit.
	pub(crate) async fn guard_forfeit_commit(&self, inputs: &[VtxoId], unlock_hash: UnlockHash) -> anyhow::Result<()> {
		if !self.expiry_payouts() {
			return Ok(());
		}
		self.guard_spend_changes(inputs).await?;
		let part = self.query_opt("SELECT id FROM round_participation WHERE unlock_hash = $1",
			&[&unlock_hash.to_string()]).await?
			.context("round participation disappeared before forfeit commit")?;
		self.guard_participation(part.get("id")).await
	}

	/// Refuse a new lightning send from a VTXO in an expired tree. The
	/// watchman blocks are locked before the VTXOs, and the expiry is
	/// compared with the tips of both daemons in the statement that checks
	/// it, after the locks. A block that arrives meanwhile only moves the
	/// tips that the check reads.
	pub(crate) async fn guard_new_lightning_inputs(&self, ids: &[VtxoId]) -> anyhow::Result<()> {
		if !self.expiry_payouts() {
			return Ok(());
		}
		self.lock_watchman_blocks().await?;
		self.guard_spend_changes(ids).await?;
		let ids = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
		if let Some(row) = self.query_opt(
			"SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) AND expiry <= GREATEST(\
				COALESCE((SELECT MAX(height) FROM captaind_block), 0), \
				COALESCE((SELECT MAX(height) FROM watchmand_block), 0)) \
				ORDER BY vtxo_id LIMIT 1", &[&ids],
		).await? {
			return Err(ExpiryPayoutRefusal::ExpiredNewLightning(row.get::<_, &str>("vtxo_id").parse()?).into());
		}
		Ok(())
	}

	/// Whether an expiry payout cancelled the round participation with the
	/// unlock hash. The tombstone outlives a deleted participation row.
	pub async fn participation_cancelled_for_payout(&self, unlock_hash: UnlockHash) -> anyhow::Result<bool> {
		Ok(self.query_opt("SELECT participation_id FROM expiry_cancelled_participation WHERE unlock_hash = $1",
			&[&unlock_hash.to_string()]).await?.is_some())
	}

	/// Whether a decision can cancel these participations, checked without
	/// locks and without writes. A decision that is dropped later must leave
	/// no cancellation behind.
	pub(crate) async fn can_cancel_expiry_participations(&self, participation_ids: &[i64]) -> anyhow::Result<bool> {
		Ok(self.cancellable_expiry_parts(participation_ids, false).await?.is_some())
	}

	/// The participations to cancel, or `None` if one of them has a stored
	/// forfeit or is gone without a cancellation. With `lock`, their inputs
	/// and rows are locked until the transaction ends.
	async fn cancellable_expiry_parts(&self, participation_ids: &[i64], lock: bool) -> anyhow::Result<Option<Vec<Row>>> {
		if participation_ids.is_empty() {
			return Ok(Some(Vec::new()));
		}
		if lock {
			let inputs = self.query("SELECT DISTINCT v.vtxo_id FROM round_part_input i \
				JOIN vtxo v ON v.vtxo_id=i.vtxo_id WHERE i.participation_id=ANY($1) ORDER BY v.vtxo_id",
				&[&participation_ids]).await?.into_iter().map(|r| r.get::<_, String>("vtxo_id")).collect::<Vec<_>>();
			self.query("SELECT vtxo_id FROM vtxo WHERE vtxo_id=ANY($1) ORDER BY vtxo_id FOR UPDATE", &[&inputs]).await?;
		}
		let parts = self.query(&format!("SELECT p.id,p.unlock_hash,p.forfeited_at,r.id AS round_db_id \
			FROM round_participation p LEFT JOIN round r ON r.funding_txid=p.round_id \
			WHERE p.id=ANY($1) ORDER BY p.id{}", if lock { " FOR UPDATE OF p" } else { "" }), &[&participation_ids]).await?;
		for id in participation_ids {
			let Some(part) = parts.iter().find(|r| r.get::<_, i64>("id") == *id) else {
				let cancelled = self.query_opt(
					"SELECT participation_id FROM expiry_cancelled_participation WHERE participation_id = $1",
					&[id],
				).await?;
				if cancelled.is_none() {
					return Ok(None);
				}
				continue;
			};
			let forfeit = self.query_opt("SELECT participation_id FROM round_part_input \
				WHERE participation_id = $1 AND signed_forfeit_tx IS NOT NULL LIMIT 1", &[id]).await?;
			if part.get::<_, Option<DateTime<Local>>>("forfeited_at").is_some() || forfeit.is_some() {
				return Ok(None);
			}
		}
		Ok(Some(parts))
	}

	/// Cancel the participations that a decision takes, under their locks.
	/// A participation whose forfeits were stored first wins. The caller
	/// must store the decision in the same transaction.
	pub async fn cancel_expiry_participations(&self, participation_ids: &[i64]) -> anyhow::Result<bool> {
		let Some(parts) = self.cancellable_expiry_parts(participation_ids, true).await? else { return Ok(false); };
		for part in parts {
			let id = part.get::<_, i64>("id");
			let hash = part.get::<_, &str>("unlock_hash");
			self.execute("INSERT INTO expiry_cancelled_participation (participation_id, unlock_hash) \
				VALUES ($1, $2) ON CONFLICT (participation_id) DO NOTHING", &[&id, &hash]).await?;
			if let Some(round) = part.get::<_, Option<i64>>("round_db_id") {
				// An input that no decision took is spendable again. The unlock
				// preimage of the participation stays guarded by its tombstone.
				self.execute("UPDATE vtxo SET spend_state='spendable',spent_in_round=NULL,updated_at=NOW() \
					WHERE spent_in_round=$1 AND oor_spent_txid IS NULL AND offboarded_in IS NULL \
					AND vtxo_id IN(SELECT vtxo_id FROM round_part_input WHERE participation_id=$2) \
					AND NOT EXISTS(SELECT 1 FROM expiry_payout_vtxo d WHERE d.vtxo_id=vtxo.vtxo_id)", &[&round, &id]).await?;
			}
		}
		Ok(true)
	}
}
