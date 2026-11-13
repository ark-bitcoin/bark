//! Recovery wallet action.
//!
//! Rebuilds the wallet's VTXO set from the seed: see [crate::recovery] for what
//! recovery reads and what it trusts the server with. Each step reads one page
//! of the xpub lookup or of a mailbox, or recovers one batch of VTXOs, and the
//! executor checkpoints after every step, so a recovery stopped by an error or a
//! crash resumes from the page or batch it was on.
//!
//! A step stores every VTXO it finds locked by this action until the server has
//! given its status, so the bodies live in the vtxo table rather than in the
//! checkpoint, and only the [RecoveryReport] and a cursor are checkpointed.
//!
//! The action is done once no VTXO is left failed. Until then it keeps its
//! checkpoint and is re-driven by every sync, however many attempts it takes.

use std::collections::HashSet;

use anyhow::Context;
use bitcoin::secp256k1::Keypair;
use log::{debug, error, info, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::MailboxAuthorization;
use ark::recovery::XpubRecoveryAuthorization;
use ark::vtxo::Full;
use server_rpc::{protos, TryFromBytes, MAX_NB_VTXO_IDS};
use server_rpc::protos::VtxoSpendState;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use crate::Wallet;
use crate::actions::{
	Advance, AdvanceError, IntoAdvanceResult, WalletAction, WalletActionCheckpoint, WalletActionId,
};
use crate::recovery::{RecoveryReport, MAX_RECOVERY_ATTEMPTS};
use crate::vtxo::{ServerStatusAdoption, VtxoLockHolder, VtxoState};

/// The id of the recovery action. A wallet recovers from one seed, so there is
/// at most one recovery at a time.
pub(crate) const RECOVERY_ACTION_ID: &str = "recovery";

/// How many passes over the failed VTXOs a drive makes before it parks.
///
/// A failed status batch is often transient, so the batch is asked again right
/// away a few times before the action waits for the next sync.
const RESOLVE_PASSES: u32 = 4;

/// The number of non-hardened child indices of an xpub.
const NB_NORMAL_CHILDREN: u32 = 1 << 31;

/// The number of keys stored per database call when revealing keys.
const KEY_REVEAL_BATCH_SIZE: u32 = 10_000;

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
	/// Ask the server for the VTXOs of our xpub's children from `start_index`,
	/// and stage and settle every one of them. The lookup comes first: it needs
	/// no backup and no gap limit, and it reveals every key up to its highest
	/// VTXO, so the mailbox scans find their keys in the database.
	/// `cursor_vtxo_id` continues the key at `start_index` where the server
	/// split its VTXOs over several responses.
	Xpub {
		start_index: u32,
		cursor_vtxo_id: Option<Vec<u8>>,
	},
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
	/// A recovery that starts at the beginning of the xpub lookup.
	pub fn new(gap_limit: u32) -> Self {
		Recovery {
			id: RECOVERY_ACTION_ID.to_string(),
			gap_limit,
			report: RecoveryReport::default(),
			progress: Progress::Xpub { start_index: 0, cursor_vtxo_id: None },
		}
	}

	pub fn id(&self) -> WalletActionId {
		self.id.clone()
	}

	/// Log what the xpub lookup and the scan of both mailboxes could not account
	/// for.
	fn log_scan_end(&self) {
		// Unmatched ids in our own seed-derived mailbox are suspicious: most
		// likely an owned VTXO whose key sits beyond the gap limit (funds may be
		// missing), not a stranger's id. Retrying won't help these — only a wider
		// gap limit can match them — so they get their own warning.
		let foreign = self.report.foreign();
		if !foreign.is_empty() {
			warn!(
				"Recovery found {} vtxo(s) not derivable from this seed within the \
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
			Progress::Xpub { start_index, cursor_vtxo_id } => {
				let next = run_xpub(
					wallet, &mut self.report, start_index, cursor_vtxo_id, &holder,
				).await.retry()?;
				self.progress = match next {
					Some((start_index, cursor_vtxo_id)) => Progress::Xpub { start_index, cursor_vtxo_id },
					None => Progress::Scanning { mailbox: RecoveryMailbox::Regular, checkpoint: 0 },
				};
				Ok(Advance::Next(self))
			},
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

				// Claim the outputs of the round participations recovery rebuilt.
				if let Err(e) = wallet.sync_pending_rounds().await {
					warn!("Error syncing recovered round participations: {:#}", e);
				}

				let report = &self.report;
				if report.failed().is_empty() {
					info!(
						"Recovery finished: recovered {} spendable vtxos ({} skipped, {} exited, \
						{} unknown to the server)",
						report.recovered().len(), report.skipped().len(),
						report.exited().len(), report.not_found().len(),
					);
					if !report.abandoned().is_empty() {
						warn!(
							"Recovery gave up on {} vtxos after {} attempts each; they are kept \
							locked as they may be spent: {:?}",
							report.abandoned().len(), MAX_RECOVERY_ATTEMPTS, report.abandoned(),
						);
					}
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

/// Ask the server for the VTXOs owned by the next range of children of our
/// VTXO xpub, from `start_index`, and stage and settle each of them.
///
/// Unlike the mailbox scans this needs no backup posted by the old wallet
/// and no gap limit: the server scans a fixed range of key indices per
/// call, and we ask for the next range for as long as the server reports
/// that more VTXOs may follow. Each VTXO comes with its body and spend
/// state, so it needs no further request. Every index up to the highest
/// one whose key matches its VTXO is stored as revealed, so the key lookups
/// of later scans resolve from the database.
///
/// A VTXO the wallet holds in any state but locked by `holder` was decided
/// before, and is only reported.
///
/// Returns the start index and cursor of the next call, or `None` when the
/// lookup is done or the server doesn't offer the rpc.
async fn run_xpub(
	wallet: &Wallet,
	report: &mut RecoveryReport,
	start_index: u32,
	cursor_vtxo_id: Option<Vec<u8>>,
	holder: &Option<VtxoLockHolder>,
) -> anyhow::Result<Option<(u32, Option<Vec<u8>>)>> {
	let (mut srv, ark_info) = wallet.require_server().await?;
	let payouts = srv.expiry_payouts().await;

	let expiry = chrono::Local::now() + std::time::Duration::from_secs(60);
	let auth = XpubRecoveryAuthorization::new(
		&wallet.inner.seed.vtxo, ark_info.server_pubkey, expiry,
	);
	let req = protos::RecoverVtxosByXpubRequest {
		xpub: wallet.vtxo_xpub().encode().to_vec(),
		start_index,
		authorization: auth.serialize(),
		cursor_vtxo_id: cursor_vtxo_id.clone(),
	};
	let resp = match srv.client.recover_vtxos_by_xpub(req).await {
		Ok(resp) => resp.into_inner(),
		Err(status) if status.code() == tonic::Code::Unimplemented => {
			info!("Server doesn't support VTXO recovery by xpub: {}", status.message());
			return Ok(None);
		},
		Err(e) => return Err(e).context("error recovering vtxos by xpub"),
	};
	debug!("Server scanned {} xpub children from index {start_index} and returned {} vtxos",
		resp.nb_keys_scanned, resp.vtxos.len(),
	);

	let staged_state = VtxoState::Locked { holder: holder.clone() };
	let mut max_index = None;
	let mut vtxos = Vec::with_capacity(resp.vtxos.len());
	for entry in resp.vtxos {
		let vtxo = match Vtxo::<Full>::deserialize(&entry.vtxo) {
			Ok(vtxo) => vtxo,
			Err(e) => {
				error!("Ignoring undecodable vtxo from the xpub lookup: {:#}", e);
				continue;
			},
		};
		if report.contains(vtxo.id()) {
			continue;
		}

		// The index is only trusted once it derives the key of the VTXO.
		let index = entry.derivation_index;
		if index >= NB_NORMAL_CHILDREN
			|| wallet.inner.seed.derive_vtxo_keypair(index).public_key() != vtxo.user_pubkey()
		{
			warn!("Recovery vtxo {} is not owned by key {index} of our xpub", vtxo.id());
			report.push_foreign(&vtxo);
			continue;
		}
		max_index = max_index.max(Some(index));
		if payouts && entry.owner_mailbox != wallet.mailbox_keypair().public_key().serialize() {
			warn!("Recovery vtxo {} has the owner mailbox of another wallet", vtxo.id());
			wallet.inner.db.remove_vtxo(vtxo.id()).await
				.context("failed to drop foreign recovery VTXO")?;
			report.push_foreign(&vtxo);
			continue;
		}

		// A step re-run after a crash finds the VTXOs it stored already.
		if let Some(stored) = wallet.inner.db.get_wallet_vtxo(vtxo.id()).await? {
			if stored.state != staged_state {
				report.push_decided(&stored);
				continue;
			}
		}

		let adoption = VtxoSpendState::try_from(entry.spend_state)
			.map_err(|_| anyhow::anyhow!(
				"server returned unknown spend state {}; this wallet may need updating",
				entry.spend_state,
			))
			.and_then(ServerStatusAdoption::from_spend_state);
		vtxos.push((vtxo, adoption));
	}

	// Keys are issued in sequence, so every index up to the highest one
	// in use is stored and new addresses continue past it.
	if let Some(max_index) = max_index {
		reveal_vtxo_keys_up_to(wallet, max_index).await
			.context("failed to store recovered vtxo keys")?;
	}
	wallet.store_recovered_vtxos(report, vtxos, holder).await?;

	// A server that moved neither past a key nor within one would have
	// us ask for the same VTXOs forever.
	let end_index = start_index.saturating_add(resp.nb_keys_scanned);
	let no_progress = end_index == start_index
		&& (resp.cursor_vtxo_id.is_none() || resp.cursor_vtxo_id == cursor_vtxo_id);
	if !resp.have_more || no_progress {
		return Ok(None);
	}
	Ok(Some((end_index, resp.cursor_vtxo_id)))
}

/// Store every VTXO key up to and including `index` as revealed.
async fn reveal_vtxo_keys_up_to(wallet: &Wallet, index: u32) -> anyhow::Result<()> {
	let mut next = wallet.inner.db.get_last_vtxo_key_index().await?.map(|i| i + 1).unwrap_or(0);
	while next <= index {
		let end = next.saturating_add(KEY_REVEAL_BATCH_SIZE).min(index + 1);
		let keys = (next..end)
			.map(|i| (i, wallet.inner.seed.derive_vtxo_keypair(i).public_key()))
			.collect::<Vec<_>>();
		wallet.inner.db.store_vtxo_keys(&keys).await?;
		next = end;
	}
	Ok(())
}

/// One page of a mailbox read for recovery.
struct RecoveryPage {
	/// Every VTXO the page references, with its body when the message carried
	/// one. Each id appears once.
	candidates: Vec<(VtxoId, Option<Vtxo<Full>>)>,
	/// The checkpoint to read the next page from.
	checkpoint: u64,
	/// Whether the mailbox has messages past this page.
	have_more: bool,
}

/// Read the page of a mailbox that follows `checkpoint` and collect every
/// VTXO its messages reference.
///
/// The paging cursor is never stored as the mailbox checkpoint: the server
/// allocates checkpoints globally across all mailboxes, so storing it would
/// make the next regular sync skip unrelated events. The regular sync still
/// processes every message from its own stored checkpoint afterwards.
async fn read_recovery_page(
	wallet: &Wallet,
	keypair: &Keypair,
	checkpoint: u64,
) -> anyhow::Result<RecoveryPage> {
	let (mut srv, _) = wallet.require_server().await?;

	// One page is read well within this window.
	let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
	let auth = MailboxAuthorization::new(keypair, expiry);
	let req = protos::mailbox_server::MailboxRequest {
		mailbox_id: auth.mailbox().serialize(),
		authorization: Some(auth.serialize()),
		checkpoint,
	};
	let resp = srv.mailbox_client.read_mailbox(req).await
		.context("error reading the mailbox for recovery")?.into_inner();

	debug!("Mailbox returned {} messages for recovery after checkpoint {checkpoint}",
		resp.messages.len());

	let mut next_checkpoint = checkpoint;
	let mut seen = HashSet::new();
	let mut candidates = Vec::new();
	for msg in &resp.messages {
		next_checkpoint = next_checkpoint.max(msg.checkpoint);

		// A message references its vtxos either by id or by full body.
		match &msg.message {
			Some(Message::RecoveryVtxoIds(m)) => {
				for raw in &m.vtxo_ids {
					let Ok(id) = VtxoId::from_bytes(raw.clone()) else {
						warn!("Ignoring undecodable recovery vtxo id: {raw:?}");
						continue;
					};
					if seen.insert(id) {
						candidates.push((id, None));
					}
				}
			},
			Some(Message::Arkoor(m)) => {
				for raw in &m.vtxos {
					let Ok(vtxo) = Vtxo::<Full>::from_bytes(raw.clone()) else {
						warn!("Ignoring undecodable arkoor vtxo: {raw:?}");
						continue;
					};
					if seen.insert(vtxo.id()) {
						candidates.push((vtxo.id(), Some(vtxo)));
					}
				}
			},
			Some(Message::RoundParticipationCompleted(_)) |
			Some(Message::IncomingLightningPayment(_)) |
			Some(Message::LightningSendFinished(_)) => {},
			None => {
				warn!("Mailbox returned a message with no content: {msg:?}");
			},
		}
	}

	// The server wants us to keep paging, but the checkpoint didn't advance,
	// so the next request would be identical and we'd loop forever. Stop
	// rather than spin on the same page.
	let mut have_more = resp.have_more;
	if have_more && next_checkpoint == checkpoint {
		warn!("Mailbox recovery made no progress at checkpoint {checkpoint}; stopping");
		have_more = false;
	}

	Ok(RecoveryPage { candidates, checkpoint: next_checkpoint, have_more })
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
	let page = read_recovery_page(wallet, keypair, checkpoint).await?;
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
