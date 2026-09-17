//! Wallet recovery from seed.
//!
//! As a wallet creates or receives VTXOs it posts their ids to a mailbox keyed
//! by a dedicated, seed-derived recovery key (see
//! [`Wallet::post_recovery_vtxo_ids`]). Recovering the seed re-derives that key
//! and reads back every posted id to rebuild the VTXO set. The regular
//! mailbox's arkoor messages are replayed too, since the recovery post is
//! best-effort and a VTXO can be missing there.
//!
//! Note that recovery is a trusted process. The server can withhold VTXOs
//! or may falsely represent spendable VTXOs as spent. Prefer to maintain
//! back-ups and use recovery from the mnemonic as a last resort.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::Keypair;
use log::{debug, info, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::mailbox::MailboxAuthorization;
use ark::vtxo::Full;
use server_rpc::TryFromBytes;
use server_rpc::protos;
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use crate::Wallet;
use crate::mailbox::MAX_MAILBOX_REQUEST_BURST;
use crate::vtxo::{ServerStatusAdoption, VtxoState};

#[derive(Debug, Default, Clone)]
pub struct RecoveryReportEntry(HashMap<VtxoId, Option<Amount>>);

impl RecoveryReportEntry {
	pub fn is_empty(&self) -> bool {
		self.0.is_empty()
	}

	pub fn len(&self) -> usize {
		self.0.len()
	}

	pub fn ids(&self) -> impl Iterator<Item = VtxoId> {
		self.0.keys().cloned()
	}

	pub fn total_amount(&self) -> Amount {
		self.0.values().filter_map(|a| *a).sum()
	}

	fn insert(&mut self, vtxo_id: VtxoId, amount: Option<Amount>) {
		if !self.0.contains_key(&vtxo_id) {
			self.0.insert(vtxo_id, amount);
		}
	}

	fn remove(&mut self, vtxo_id: VtxoId) {
		self.0.remove(&vtxo_id);
	}
}

/// Summary of a recovery scan over the mailboxes.
///
/// `skipped` vs `failed` is the load-bearing distinction: a `skipped` VTXO was
/// *decided* not to be spendable (spent, exited on-chain, or reported
/// non-spendable), whereas a `failed` VTXO could not be decided due to an error.
/// A non-empty `failed` or `foreign` set means funds may be missing, so it must
/// not be taken for a complete recovery. Ids are kept (not counted) so a caller
/// can log or retry the exact VTXOs.
#[derive(Debug, Default, Clone)]
pub struct RecoveryReport {
	/// Spendable VTXOs that were successfully re-imported.
	recovered: RecoveryReportEntry,
	/// VTXOs deliberately left out: reported spent or still in-flight by the
	/// server.
	skipped: RecoveryReportEntry,
	/// VTXOs recovery could not decide on: the fetch, validation, or status
	/// request failed.
	failed: RecoveryReportEntry,
	/// VTXOs found in the mailbox whose key we could not derive within the gap
	/// limit. Only the seed owner can post here, so these are most likely our own
	/// VTXOs whose key sits beyond the gap limit; their presence means funds may
	/// be missing and the scan can't be reported complete.
	foreign: RecoveryReportEntry,
	/// VTXOs that have been fully exited on-chain.
	exited: RecoveryReportEntry,
}

impl RecoveryReport {
	/// Whether the scan accounted for every VTXO in the mailbox.
	///
	/// A `failed` VTXO or `foreign` id both mean funds may be missing, so neither
	/// may be present. `failed` is retryable; a `foreign` id instead needs a wider
	/// gap limit to be matched.
	pub fn is_complete(&self) -> bool {
		self.failed.is_empty() && self.foreign.is_empty()
	}

	pub fn recovered(&self) -> &RecoveryReportEntry {
		&self.recovered
	}

	pub fn push_recovered<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.recovered.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn skipped(&self) -> &RecoveryReportEntry {
		&self.skipped
	}

	pub fn push_skipped<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.skipped.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn foreign(&self) -> &RecoveryReportEntry {
		&self.foreign
	}

	pub fn push_foreign<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.foreign.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn failed(&self) -> &RecoveryReportEntry {
		&self.failed
	}

	pub fn push_failed(&mut self, id: VtxoId, amount: Option<Amount>) {
		self.failed.insert(id, amount);
	}

	pub fn exited(&self) -> &RecoveryReportEntry {
		&self.exited
	}

	pub fn push_exited<G>(&mut self, vtxo: &Vtxo<G>) {
		self.failed.remove(vtxo.id());
		self.exited.insert(vtxo.id(), Some(vtxo.amount()));
	}
}

/// Outcome of the recovery scan on wallet open.
///
/// [`crate::OpenWalletArgs::on_recovery_finished`] is called exactly once per
/// successful open, with one of these. A caller never has to read meaning into
/// the callback staying silent: not running and failing are both stated.
#[derive(Debug)]
pub enum RecoveryStatus {
	/// No scan was attempted: the wallet already existed, or the caller set
	/// [`crate::OpenWalletArgs::skip_recovery`].
	NotRun,
	/// The scan errored before it could produce a report. Nothing is known about
	/// the mailbox's VTXOs, so funds may be missing until a retry succeeds.
	Failed(anyhow::Error),
	/// The scan ran to the end. Check [`RecoveryReport::is_complete`]: a finished
	/// scan can still leave individual VTXOs unaccounted for.
	Completed(RecoveryReport),
}

impl Wallet {
	/// Page a mailbox from checkpoint 0 and recover every VTXO it references.
	///
	/// Ids already in `seen` are skipped, so a VTXO both mailboxes know about is
	/// handled once.
	///
	/// The paging cursor is never persisted: the server allocates checkpoints
	/// globally across all mailboxes, so storing it would make the next regular
	/// sync skip unrelated events. The regular sync still processes every message
	/// from its own stored checkpoint afterwards.
	async fn scan_mailbox_for_recovery(
		&self,
		report: &mut RecoveryReport,
		keypair: &Keypair,
		gap_limit: u32,
		seen: &mut HashSet<VtxoId>,
	) -> anyhow::Result<()> {
		let (mut srv, _) = self.require_server().await?;

		// The paging burst should be done well within this window.
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
		let auth = MailboxAuthorization::new(keypair, expiry);
		let mailbox_id = auth.mailbox();

		let mut checkpoint = 0u64;
		for iteration in 1..=MAX_MAILBOX_REQUEST_BURST {
			let req = protos::mailbox_server::MailboxRequest {
				mailbox_id: mailbox_id.serialize(),
				authorization: Some(auth.serialize()),
				checkpoint,
			};
			let resp = srv.mailbox_client.read_mailbox(req).await
				.context("error reading the mailbox for recovery")?.into_inner();

			debug!("Mailbox returned {} messages on recovery iteration {iteration}",
				resp.messages.len());

			let prev_checkpoint = checkpoint;
			for msg in &resp.messages {
				checkpoint = checkpoint.max(msg.checkpoint);

				// A message references its vtxos either by id or by full body.
				match &msg.message {
					Some(Message::RecoveryVtxoIds(m)) => {
						for raw in &m.vtxo_ids {
							let Ok(id) = VtxoId::from_bytes(raw.clone()) else {
								warn!("Ignoring undecodable recovery vtxo id: {raw:?}");
								continue;
							};
							if seen.insert(id) {
								self.recover_candidate(report, id, None, gap_limit).await?;
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
								let id = vtxo.id();
								self.recover_candidate(report, id, Some(vtxo), gap_limit).await?;
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

			if !resp.have_more {
				break;
			}

			// The server wants us to keep paging, but the checkpoint didn't
			// advance, so the next request would be identical and we'd loop
			// forever. Stop rather than spin on the same page.
			if checkpoint == prev_checkpoint {
				warn!("Mailbox recovery iteration {iteration} made no progress \
					at checkpoint {checkpoint}; stopping");
				break;
			}
		}

		Ok(())
	}

	/// Fetch the full [`Vtxo<Full>`] for `id` from the server.
	///
	/// The recovery mailbox only stores ids, so we ask the server for the full
	/// VTXO data. The result is untrusted until validated by the caller.
	pub(crate) async fn fetch_vtxo(&self, id: VtxoId) -> anyhow::Result<Vtxo<Full>> {
		let (mut srv, _) = self.require_server().await?;
		let resp = srv.client.get_vtxo(protos::GetVtxoRequest {
			vtxo_id: id.to_bytes().to_vec(),
		}).await.with_context(|| format!("error fetching vtxo {id} from server"))?.into_inner();

		Vtxo::<Full>::deserialize(&resp.vtxo)
			.with_context(|| format!("server returned an undecodable vtxo for {id}"))
	}

	/// Check if a VTXO is confirmed on-chain.
	///
	/// If it is, we store it as exited and return `true`.
	/// If we could not confirm the exit status, we consider it is not exited yet and return `false`.
	async fn check_vtxo_onchain_status(
		&self,
		report: &mut RecoveryReport,
		vtxo: &Vtxo<Full>,
	) -> anyhow::Result<bool> {
		// An off-chain VTXO's tx is only confirmed once it has been exited,
		// so if we see it on-chain the funds live in the on-chain wallet and
		// it must not be recovered as spendable. The server's spend status
		// doesn't capture unilateral exits, so we check the chain ourselves.
		match self.inner.chain.tx_confirmed(vtxo.point().txid).await {
			Ok(Some(height)) => {
				// A row from an earlier, failed recovery attempt is forced along.
				self.store_vtxos([vtxo], &VtxoState::Exited).await?;
				self.mark_vtxos_as_exited(&[vtxo.id()]).await?;
				self.exit_mgr()
					.start_exit_for_vtxos_including_non_standard(&[vtxo.to_bare()]).await?;
				report.push_exited(vtxo);
				debug!("Skipping recovery vtxo {}: confirmed on-chain at height {height} (exited)", vtxo.id());
				Ok(true)
			},
			// If we could not confirm the exit status, we consider it is not exited yet.
			// If it actually is, next wallet sync will handle it properly
			Ok(None) | Err(_) => Ok(false),
		}
	}

	/// Recover a single VTXO: check we own it, ask the server for its status, and
	/// store it in the matching state.
	///
	/// `vtxo` is the body when the mailbox message carried one; otherwise it is
	/// fetched from the server.
	async fn recover_candidate(
		&self,
		report: &mut RecoveryReport,
		id: VtxoId,
		vtxo: Option<Vtxo<Full>>,
		gap_limit: u32,
	) -> anyhow::Result<()> {
		let vtxo = match vtxo {
			Some(vtxo) => vtxo,
			None => match self.fetch_vtxo(id).await {
				Ok(vtxo) => vtxo,
				Err(e) => {
					warn!("Could not fetch recovery vtxo {id}: {:#}", e);
					report.push_failed(id, None);
					return Ok(());
				},
			},
		};

		// [`Wallet::find_vtxo_keypairs`] persists the keys it reveals, so each
		// match extends the window the next candidate is scanned against.
		let keypairs = self.find_vtxo_keypairs([vtxo.user_pubkey()], gap_limit).await?;
		let Some(keypair) = keypairs.get(&vtxo.user_pubkey()) else {
			report.push_foreign(&vtxo);
			return Ok(());
		};

		// A validation error (anchor not yet visible, or invalid) is a
		// non-decision, so it's a failure, not a clean skip.
		if let Err(e) = self.validate_vtxo(&vtxo).await {
			warn!("Could not validate recovery vtxo {id}: {:#}", e);
			report.push_failed(id, Some(vtxo.amount()));
			return Ok(());
		}

		if self.check_vtxo_onchain_status(report, &vtxo).await? {
			return Ok(());
		}

		// The server is the authority on whether it was spent elsewhere,
		// and recovery has nothing else to go on.
		let adoption = self.fetch_vtxo_spend_state(id, keypair).await
			.and_then(ServerStatusAdoption::from_spend_state);

		// NB we don't use store_spendable_vtxos to avoid posting the vtxo again
		match adoption {
			Ok(ServerStatusAdoption::Spendable) => {
				self.store_vtxos([&vtxo], &VtxoState::Spendable).await?;
				report.push_recovered(&vtxo);
				debug!("Recovered spendable vtxo {id} ({})", vtxo.amount());
			},
			// The spent row is what stops a later mailbox replay from storing
			// the vtxo as spendable again.
			Ok(ServerStatusAdoption::Spent) => {
				debug!("Recovery vtxo {id} already spent, skipping");
				// A spendable row from an earlier, failed attempt is forced along.
				self.store_vtxos([&vtxo], &VtxoState::Spent).await?;
				self.mark_vtxos_as_spent(&[id]).await?;
				report.push_skipped(&vtxo);
			},
			// Finishing the flow the VTXO is stuck in is what decides where it
			// belongs, so nothing is stored. Arkoor mailbox messages only carry
			// final Pubkey-policy VTXOs, so the replay cannot bring an in-flight
			// one back.
			Ok(ServerStatusAdoption::InFlight(state)) => {
				debug!("Recovery vtxo {id} not spendable ({state:?}), skipping");
				self.inner.db.remove_vtxo(id).await
					.context("Failed to drop in-flight recovery vtxo")?;
				report.push_skipped(&vtxo);
			},
			// No usable answer — a non-decision, so it's retried rather than taken
			// for a clean skip. The spendable row overstates the balance until the
			// retry, but no row at all would let a mailbox replay store the vtxo
			// spendable without ever asking the server.
			Err(e) => {
				warn!("Could not get status for recovery vtxo {id}: {:#}", e);
				self.store_vtxos([&vtxo], &VtxoState::Spendable).await?;
				report.push_failed(id, Some(vtxo.amount()));
			},
		}

		Ok(())
	}

	/// Recover the given VTXOs into this wallet's spendable set.
	///
	/// `gap_limit` overrides [`crate::Config::vtxo_key_gap_limit`] for the key
	/// scan that decides which of `ids` this wallet owns.
	pub async fn recover_vtxos(
		&self,
		ids: impl IntoIterator<Item = VtxoId>,
		gap_limit: Option<u32>,
	) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();
		let gap_limit = gap_limit.unwrap_or(self.inner.config.vtxo_key_gap_limit);
		for id in ids {
			self.recover_candidate(&mut report, id, None, gap_limit).await?;
		}
		Ok(report)
	}

	/// Rebuild the wallet's VTXO set from the seed-derived recovery mailbox and
	/// the arkoor messages in the regular mailbox.
	///
	/// Both mailboxes are read from checkpoint 0, and every VTXO they reference
	/// is resolved against the chain and the server as it is seen and stored
	/// accordingly. Returns a [`RecoveryReport`] (see it for why
	/// recovered/skipped/failed matters).
	pub(crate) async fn recover_from_mailbox(&self) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();
		let gap_limit = self.inner.config.vtxo_key_gap_limit;
		let mut seen = HashSet::new();

		// The regular mailbox comes first: its arkoor messages carry full vtxos,
		// so a duplicate in the recovery mailbox needs no fetch.
		let keypair = self.mailbox_keypair();
		self.scan_mailbox_for_recovery(&mut report, &keypair, gap_limit, &mut seen).await?;

		let keypair = self.recovery_mailbox_keypair();
		self.scan_mailbox_for_recovery(&mut report, &keypair, gap_limit, &mut seen).await?;

		// Unmatched ids in our own seed-derived mailbox are suspicious: most
		// likely an owned VTXO whose key sits beyond the gap limit (funds may be
		// missing), not a stranger's id. Retrying won't help these — only a wider
		// gap limit can match them — so they get their own warning.
		if !report.foreign.is_empty() {
			warn!(
				"Recovery mailbox held {} vtxo(s) not derivable from this seed within the \
				gap limit ({gap_limit}); if any are ours they were not recovered: {:?}",
				report.foreign.len(), report.foreign,
			);
		}

		if report.is_complete() {
			info!(
				"Recovered {} spendable vtxos from the recovery mailbox ({} skipped)",
				report.recovered.len(), report.skipped.len(),
			);
		}

		// We retry 3 times to recover the failed VTXOs.
		for _ in 0..3 {
			if report.failed.is_empty() {
				break;
			}

			let ids = report.failed.ids().collect::<Vec<_>>();
			for id in ids {
				self.recover_candidate(&mut report, id, None, gap_limit).await?;
			}
		}

		if !report.failed.is_empty() {
			warn!(
				"Recovery incomplete: recovered {} spendable vtxos, but {} could not be \
				checked due to errors; funds may be missing — retry recovery to recover \
				them ({} skipped). Failed vtxos: {:?}",
				report.recovered.len(), report.failed.len(),
				report.skipped.len(), report.failed,
			);
		}

		Ok(report)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::Amount;
	use bitcoin::hashes::Hash;

	fn dummy_id(vout: u32) -> VtxoId {
		bitcoin::OutPoint::new(bitcoin::Txid::all_zeros(), vout).into()
	}

	/// `is_complete` hinges on whether any VTXO went unaccounted for: a `skipped`
	/// VTXO is a clean decision, whereas a `failed` VTXO or a `foreign` id both
	/// mean funds may be missing and the scan is incomplete.
	#[test]
	fn recovery_report_completeness() {
		let clean = RecoveryReport {
			recovered: RecoveryReportEntry(HashMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			skipped: RecoveryReportEntry(HashMap::from([(dummy_id(1), Some(Amount::from_sat(1000)))])),
			foreign: RecoveryReportEntry(HashMap::new()),
			failed: RecoveryReportEntry(HashMap::new()),
			exited: RecoveryReportEntry(HashMap::new()),
		};
		assert!(clean.is_complete(),
			"recovered and skipped VTXOs are clean decisions, not failures");

		assert!(RecoveryReport::default().is_complete(),
			"an empty report is trivially complete");
		assert!(!RecoveryReport {
			failed: RecoveryReportEntry(HashMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a failed VTXO means recovery is incomplete");
		assert!(!RecoveryReport {
			foreign: RecoveryReportEntry(HashMap::from([(dummy_id(2), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a foreign id is likely an owned VTXO beyond the gap limit, so recovery is incomplete");
	}
}

