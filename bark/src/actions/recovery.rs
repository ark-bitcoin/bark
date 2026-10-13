//! Recovery wallet action.
//!
//! Rebuilds the wallet's VTXO set from the seed: see [crate::recovery] for what
//! recovery reads and what it trusts the server with. Each step reads one
//! mailbox page or recovers one batch of VTXOs, and the executor checkpoints
//! after every step, so a recovery stopped by an error or a crash resumes from
//! the page or batch it was on.
//!
//! A step stores every VTXO it finds locked by this action until the server has
//! given its status, so the bodies live in the vtxo table rather than in the
//! checkpoint, and only the [RecoveryReport] and a cursor are checkpointed.
//!
//! The action is done once no VTXO is left failed. Until then it keeps its
//! checkpoint and is re-driven by every sync, however many attempts it takes.

use bitcoin::secp256k1::Keypair;
use log::{info, warn};

use ark::VtxoId;
use server_rpc::MAX_NB_VTXO_IDS;

use crate::Wallet;
use crate::actions::{
	Advance, AdvanceError, IntoAdvanceResult, WalletAction, WalletActionCheckpoint, WalletActionId,
};
use crate::recovery::RecoveryReport;
use crate::vtxo::VtxoLockHolder;

/// The id of the recovery action. A wallet recovers from one seed, so there is
/// at most one recovery at a time.
pub(crate) const RECOVERY_ACTION_ID: &str = "recovery";

/// How many passes over the failed VTXOs a drive makes before it parks.
///
/// A failed status batch is often transient, so the batch is asked again right
/// away a few times before the action waits for the next sync.
const RESOLVE_PASSES: u32 = 4;

/// The lock holder of every VTXO recovery staged but did not decide on yet.
pub(crate) fn recovery_lock_holder() -> VtxoLockHolder {
	VtxoLockHolder::Action { id: RECOVERY_ACTION_ID.to_string() }
}

/// The mailboxes recovery reads, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryMailbox {
	/// The regular mailbox. Its arkoor messages carry full VTXOs, so it is read
	/// first and a VTXO the recovery mailbox also lists needs no fetch.
	Regular,
	/// The seed-derived recovery mailbox, which lists VTXO ids only.
	Recovery,
}

/// An in-progress recovery from seed, persisted as a single checkpoint row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
	pub id: WalletActionId,
	/// The key gap limit the scan was started with.
	pub gap_limit: u32,
	/// What every step so far decided. Its failed VTXOs are what the action
	/// still has to recover.
	pub report: RecoveryReport,
	pub progress: Progress,
}

/// The phases of a recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Progress {
	/// Read the page of `mailbox` that follows `checkpoint`, and stage every VTXO
	/// it references.
	Scanning {
		mailbox: RecoveryMailbox,
		checkpoint: u64,
	},
	/// Both mailboxes are read. Recover the failed VTXOs one batch at a time,
	/// walking them in id order from `after`. `pass` counts the walks of this
	/// drive.
	Resolving {
		after: Option<VtxoId>,
		pass: u32,
	},
}

impl Recovery {
	/// A recovery that starts at the beginning of the regular mailbox.
	pub fn new(gap_limit: u32) -> Self {
		Recovery {
			id: RECOVERY_ACTION_ID.to_string(),
			gap_limit,
			report: RecoveryReport::default(),
			progress: Progress::Scanning { mailbox: RecoveryMailbox::Regular, checkpoint: 0 },
		}
	}

	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	/// Log what the scan of both mailboxes could not account for.
	fn log_scan_end(&self) {
		// Unmatched ids in our own seed-derived mailbox are suspicious: most
		// likely an owned VTXO whose key sits beyond the gap limit (funds may be
		// missing), not a stranger's id. Retrying won't help these — only a wider
		// gap limit can match them — so they get their own warning.
		let foreign = self.report.foreign();
		if !foreign.is_empty() {
			warn!(
				"Recovery mailbox held {} vtxo(s) not derivable from this seed within the \
				gap limit ({}); if any are ours they were not recovered: {:?}",
				foreign.len(), self.gap_limit, foreign,
			);
		}
	}
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WalletAction for Recovery {
	fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	fn from_checkpoint(checkpoint: WalletActionCheckpoint) -> Option<Self> {
		checkpoint.into_recovery()
	}

	/// The VTXOs recovery holds are not counted: until the server has given their
	/// status they may well be spent.
	fn pending_balance_vtxo_ids(&self) -> Vec<VtxoId> {
		Vec::new()
	}

	async fn advance(mut self, wallet: &Wallet) -> Result<Advance<Self>, AdvanceError> {
		let holder = Some(recovery_lock_holder());
		match self.progress {
			Progress::Scanning { mailbox, checkpoint } => {
				let keypair = match mailbox {
					RecoveryMailbox::Regular => wallet.mailbox_keypair(),
					RecoveryMailbox::Recovery => wallet.recovery_mailbox_keypair(),
				};
				let next = run_scan(
					wallet, &mut self.report, &keypair, checkpoint, self.gap_limit, &holder,
				).await.retry()?;

				self.progress = match (next, mailbox) {
					(Some(checkpoint), mailbox) => Progress::Scanning { mailbox, checkpoint },
					(None, RecoveryMailbox::Regular) => Progress::Scanning {
						mailbox: RecoveryMailbox::Recovery,
						checkpoint: 0,
					},
					(None, RecoveryMailbox::Recovery) => {
						self.log_scan_end();
						Progress::Resolving { after: None, pass: 0 }
					},
				};
				Ok(Advance::Next(self))
			},
			Progress::Resolving { after, pass } => {
				let last = run_resolve(
					wallet, &mut self.report, after, self.gap_limit, &holder,
				).await.retry()?;
				if let Some(last) = last {
					self.progress = Progress::Resolving { after: Some(last), pass };
					return Ok(Advance::Next(self));
				}

				let report = &self.report;
				if report.failed().is_empty() {
					info!(
						"Recovery finished: recovered {} spendable vtxos ({} skipped, {} exited, \
						{} unknown to the server)",
						report.recovered().len(), report.skipped().len(),
						report.exited().len(), report.not_found().len(),
					);
					*wallet.inner.finished_recovery.lock() = Some(self.report);
					return Ok(Advance::Done);
				}

				if pass + 1 < RESOLVE_PASSES {
					self.progress = Progress::Resolving { after: None, pass: pass + 1 };
					return Ok(Advance::Next(self));
				}

				warn!(
					"Recovery incomplete: recovered {} spendable vtxos, but {} could not be \
					checked yet and are kept locked; recovery resumes on the next sync. \
					Failed vtxos: {:?}",
					report.recovered().len(), report.failed().len(), report.failed(),
				);
				self.progress = Progress::Resolving { after: None, pass: 0 };
				Ok(Advance::Park { state: self, wake_after: None, error: None })
			},
		}
	}

	/// Recovery has nothing to undo: the step is asked again on the next drive.
	async fn on_abort(self, _wallet: &Wallet, error: anyhow::Error) -> Advance<Self> {
		Advance::Retry { state: self, error }
	}
}

/// Stage every VTXO of the mailbox page that follows `checkpoint`.
///
/// Ids the report already holds were handled by an earlier page or mailbox
/// and are left out. Returns the checkpoint of the next page, or `None` when
/// the mailbox has no more pages.
async fn run_scan(
	wallet: &Wallet,
	report: &mut RecoveryReport,
	keypair: &Keypair,
	checkpoint: u64,
	gap_limit: u32,
	holder: &Option<VtxoLockHolder>,
) -> anyhow::Result<Option<u64>> {
	let page = wallet.read_recovery_page(keypair, checkpoint).await?;
	let candidates = page.candidates.into_iter()
		.filter(|(id, _)| !report.contains(*id))
		.collect();
	wallet.stage_recovery_candidates(report, candidates, gap_limit, holder).await?;
	Ok(page.have_more.then_some(page.checkpoint))
}

/// Recover the next batch of failed VTXOs, the ones with an id past `after`.
///
/// A batch holds at most [`MAX_NB_VTXO_IDS`] VTXOs, so its status is asked in
/// a single request. Returns the last id of the batch, or `None` when no
/// failed VTXO is past `after`.
async fn run_resolve(
	wallet: &Wallet,
	report: &mut RecoveryReport,
	after: Option<VtxoId>,
	gap_limit: u32,
	holder: &Option<VtxoLockHolder>,
) -> anyhow::Result<Option<VtxoId>> {
	let batch = report.failed().ids_after(after, MAX_NB_VTXO_IDS);
	let Some(last) = batch.last().copied() else {
		return Ok(None);
	};
	let candidates = batch.into_iter().map(|id| (id, None)).collect();
	wallet.recover_candidates(report, candidates, gap_limit, holder).await?;
	Ok(Some(last))
}

#[cfg(test)]
mod test {
	use super::*;

	use bitcoin::Amount;
	use bitcoin::hashes::Hash;

	use crate::actions::WalletActionCheckpoint;

	#[test]
	fn recovery_checkpoint_roundtrips() {
		let id = VtxoId::from(bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), 1));
		let mut recovery = Recovery::new(20);
		recovery.report.push_failed(id, Some(Amount::from_sat(1_000)));
		recovery.progress = Progress::Resolving { after: Some(id), pass: 2 };

		let checkpoint = WalletActionCheckpoint::from(recovery.clone());
		let json = serde_json::to_vec(&checkpoint).unwrap();
		let decoded: WalletActionCheckpoint = serde_json::from_slice(&json).unwrap();
		assert_eq!(decoded.into_recovery(), Some(recovery));
	}
}
