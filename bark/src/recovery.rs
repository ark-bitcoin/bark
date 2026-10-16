//! Wallet recovery from seed.
//!
//! Two sources are combined to rebuild the VTXO set.
//!
//! The server can list the VTXOs owned by the children of the wallet's VTXO
//! xpub (see [`Wallet::vtxo_xpub`]), each with its body, its spend state and
//! the child index of its key. That needs no backup from the old wallet and no
//! gap limit on our side: the server scans a fixed range of key indices per
//! request, stops after a run of unused keys, and the wallet requests the next
//! range while the server reports that more VTXOs may follow.
//!
//! As a wallet creates or receives VTXOs it also posts their ids to a mailbox
//! keyed by a dedicated, seed-derived recovery key (see
//! [`Wallet::post_recovery_vtxo_ids`]). Recovering the seed re-derives that key
//! and reads back every posted id. The regular mailbox's arkoor messages are
//! replayed too, since the recovery post is best-effort and a VTXO can be
//! missing there.
//!
//! Note that recovery is a trusted process. The server can withhold VTXOs
//! or may falsely represent spendable VTXOs as spent. Its word on the spend
//! state is final: a VTXO it reports spent is stored spent without being
//! validated, and only a VTXO it reports spendable is validated and checked
//! against the chain. Prefer to maintain back-ups and use recovery from the
//! mnemonic as a last resort.

use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bitcoin::Amount;
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
use crate::vtxo::{ServerStatusAdoption, VtxoState};

/// The number of non-hardened child indices of an xpub.
const NB_NORMAL_CHILDREN: u32 = 1 << 31;

/// The number of keys stored per database call when revealing keys.
const KEY_REVEAL_BATCH_SIZE: u32 = 10_000;

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

	fn contains(&self, vtxo_id: VtxoId) -> bool {
		self.0.contains_key(&vtxo_id)
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
	/// VTXO ids the server reported as unknown. Recovery trusts the server, so
	/// these are not retried.
	not_found: RecoveryReportEntry,
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

	/// Whether this scan already handled the VTXO, whatever the outcome.
	pub fn seen(&self, vtxo_id: VtxoId) -> bool {
		self.recovered.contains(vtxo_id)
			|| self.skipped.contains(vtxo_id)
			|| self.failed.contains(vtxo_id)
			|| self.foreign.contains(vtxo_id)
			|| self.exited.contains(vtxo_id)
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

	pub fn not_found(&self) -> &RecoveryReportEntry {
		&self.not_found
	}

	pub fn push_not_found(&mut self, id: VtxoId) {
		self.failed.remove(id);
		self.not_found.insert(id, None);
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

		// Paging the whole mailbox should be done well within this window. The
		// server rejects an expired authorization, which also ends the scan of
		// a server that never stops serving pages.
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(10 * 60);
		let auth = MailboxAuthorization::new(keypair, expiry);
		let mailbox_id = auth.mailbox();

		// Recovery stores no paging checkpoint, so a page left unread is never
		// read. The scan ends when the server has no more messages.
		let mut checkpoint = 0u64;
		let mut iteration = 0usize;
		loop {
			iteration += 1;
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
			let mut candidates = Vec::new();
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

			// One batch per page bounds the memory to what the server sends at once.
			self.recover_candidates(report, candidates, gap_limit).await?;

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

	/// Fetch the full [`Vtxo<Full>`] of every id in `ids` from the server, in
	/// batches of [`MAX_NB_VTXO_IDS`].
	///
	/// The recovery mailbox only stores ids, so we ask the server for the full
	/// VTXO data. The result is untrusted until validated by the caller.
	///
	/// Returns the fetched VTXOs and the ids the server does not know. An id
	/// whose batch request failed is in neither. Only a server that cannot be
	/// reached is an error.
	pub(crate) async fn fetch_vtxos(
		&self,
		ids: &[VtxoId],
	) -> anyhow::Result<(HashMap<VtxoId, Vtxo<Full>>, HashSet<VtxoId>)> {
		let mut ret = HashMap::with_capacity(ids.len());
		let mut missing = HashSet::new();
		if ids.is_empty() {
			return Ok((ret, missing));
		}

		let (mut srv, _) = self.require_server().await?;
		let wanted = ids.iter().copied().collect::<HashSet<_>>();
		for chunk in ids.chunks(MAX_NB_VTXO_IDS) {
			let req = protos::GetVtxosByIdsRequest {
				vtxo_ids: chunk.iter().map(|id| id.to_bytes().to_vec()).collect(),
			};
			let resp = match srv.client.get_vtxos_by_ids(req).await {
				Ok(resp) => resp.into_inner(),
				Err(e) => {
					warn!("Could not fetch {} recovery vtxos from server: {:#}", chunk.len(), e);
					continue;
				},
			};

			for raw in &resp.missing_vtxo_ids {
				match VtxoId::from_bytes(raw) {
					Ok(id) => {
						warn!("Could not fetch recovery vtxo {id}: unknown to the server");
						missing.insert(id);
					},
					Err(_) => warn!("Server reported an undecodable missing vtxo id: {raw:?}"),
				}
			}

			// Unknown ids are left out of the response, so the position of a
			// body says nothing about which id it answers.
			for raw in &resp.vtxos {
				let vtxo = match Vtxo::<Full>::deserialize(raw) {
					Ok(vtxo) => vtxo,
					Err(e) => {
						warn!("Server returned an undecodable recovery vtxo: {:#}", e);
						continue;
					},
				};
				if !wanted.contains(&vtxo.id()) {
					warn!("Server returned recovery vtxo {} that was not requested", vtxo.id());
					continue;
				}
				ret.insert(vtxo.id(), vtxo);
			}
		}

		Ok((ret, missing))
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

	/// Recover a set of VTXOs: fetch the bodies the mailbox did not carry, check
	/// we own them, ask the server for their status, and store them in the
	/// matching state, see [Self::store_recovered_vtxos].
	///
	/// A candidate's body is given when the mailbox message carried one;
	/// otherwise it is fetched from the server.
	async fn recover_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<(VtxoId, Option<Vtxo<Full>>)>,
		gap_limit: u32,
	) -> anyhow::Result<()> {
		// A repeated id finds its fetched body already taken and would be
		// reported failed.
		let mut seen = HashSet::new();
		let candidates = candidates.into_iter()
			.filter(|(id, _)| seen.insert(*id))
			.collect::<Vec<_>>();

		let to_fetch = candidates.iter()
			.filter(|(_, vtxo)| vtxo.is_none())
			.map(|(id, _)| *id)
			.collect::<Vec<_>>();
		let (mut fetched, missing) = self.fetch_vtxos(&to_fetch).await?;

		let mut vtxos = Vec::with_capacity(candidates.len());
		for (id, vtxo) in candidates {
			// The fetch logged why the body is missing.
			match vtxo.or_else(|| fetched.remove(&id)) {
				Some(vtxo) => vtxos.push(vtxo),
				None if missing.contains(&id) => report.push_not_found(id),
				None => report.push_failed(id, None),
			}
		}

		// One key scan for the whole batch. [`Wallet::find_vtxo_keypairs`] widens
		// its window on every match, so later keys of the batch are found however
		// the candidates are ordered.
		let pubkeys = vtxos.iter().map(|v| v.user_pubkey()).collect::<Vec<_>>();
		let keypairs = self.find_vtxo_keypairs(pubkeys, gap_limit).await?;
		let mut owned = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			match keypairs.get(&vtxo.user_pubkey()) {
				Some(keypair) => owned.push((vtxo, *keypair)),
				None => report.push_foreign(&vtxo),
			}
		}

		// The server is the authority on whether a vtxo was spent elsewhere,
		// and recovery has nothing else to go on.
		let queries = owned.iter().map(|(vtxo, keypair)| (vtxo.id(), keypair)).collect::<Vec<_>>();
		let states = self.fetch_vtxo_spend_states(&queries).await?;

		let vtxos = owned.into_iter().map(|(vtxo, _)| {
			// The fetch logged why an answer is missing.
			let adoption = match states.get(&vtxo.id()) {
				Some(state) => ServerStatusAdoption::from_spend_state(*state),
				None => Err(anyhow::anyhow!("no answer from the server")),
			};
			(vtxo, adoption)
		}).collect();
		self.store_recovered_vtxos(report, vtxos).await
	}

	/// Store owned VTXOs in the state the server reported for them.
	///
	/// The server's word on the spend state is final, so it is taken before any
	/// chain lookup: a VTXO it reports spent is stored spent as is, and only a
	/// VTXO it reports spendable is validated and checked for an exit. Rows are
	/// written once per state, not once per VTXO.
	async fn store_recovered_vtxos(
		&self,
		report: &mut RecoveryReport,
		vtxos: Vec<(Vtxo<Full>, anyhow::Result<ServerStatusAdoption>)>,
	) -> anyhow::Result<()> {
		let mut spendable = Vec::new();
		let mut spent = Vec::new();
		let mut unclaimed = Vec::new();
		let mut locked = Vec::new();
		for (vtxo, adoption) in vtxos {
			let id = vtxo.id();
			match adoption {
				Ok(ServerStatusAdoption::Spendable) => spendable.push(vtxo),
				Ok(ServerStatusAdoption::Spent) => spent.push(vtxo),
				Ok(ServerStatusAdoption::InFlight(VtxoSpendState::Unclaimed))
					if vtxo.unlock_hash().is_some() => unclaimed.push(vtxo),
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
				Err(e) => {
					warn!("Could not get status for recovery vtxo {id}: {:#}", e);
					locked.push(vtxo);
				},
			}
		}

		// The spent row is what stops a later mailbox replay from storing the
		// vtxo as spendable again. A row from an earlier, failed attempt is
		// forced along.
		if !spent.is_empty() {
			self.store_vtxos(spent.iter(), &VtxoState::Spent).await?;
			self.mark_vtxos_as_spent(spent.iter().map(|v| v.id())).await?;
			for vtxo in &spent {
				debug!("Recovery vtxo {} already spent, skipping", vtxo.id());
				report.push_skipped(vtxo);
			}
		}

		// An unclaimed output of a delegated round participation lacks its
		// unlock preimage, so it can't validate yet. The participation is
		// rebuilt instead, and the round sync claims the output.
		for vtxo in unclaimed {
			let id = vtxo.id();
			let unlock_hash = vtxo.unlock_hash().expect("checked above");
			match self.recover_delegated_participation(unlock_hash).await {
				Ok(()) => {
					debug!("Recovery vtxo {id} is an unclaimed round output, left to the round sync");
					report.push_skipped(&vtxo);
				},
				Err(e) => {
					warn!("Could not recover the round participation of vtxo {id}: {:#}", e);
					report.push_failed(id, Some(vtxo.amount()));
				},
			}
		}

		// Only a vtxo the server lets us spend is worth the chain lookups.
		let mut recovered = Vec::with_capacity(spendable.len());
		for vtxo in spendable {
			// A validation error (anchor not yet visible, or invalid) is a
			// non-decision, so it's a failure, not a clean skip.
			if let Err(e) = self.validate_vtxo(&vtxo).await {
				warn!("Could not validate recovery vtxo {}: {:#}", vtxo.id(), e);
				report.push_failed(vtxo.id(), Some(vtxo.amount()));
				continue;
			}
			if self.check_vtxo_onchain_status(report, &vtxo).await? {
				continue;
			}
			recovered.push(vtxo);
		}
		// NB we don't use store_spendable_vtxos to avoid posting the vtxos again
		if !recovered.is_empty() {
			self.store_vtxos(recovered.iter(), &VtxoState::Spendable).await?;
			// A locked row from an earlier attempt without an answer is released.
			self.unlock_vtxos(recovered.iter(), None).await?;
			for vtxo in &recovered {
				debug!("Recovered spendable vtxo {} ({})", vtxo.id(), vtxo.amount());
				report.push_recovered(vtxo);
			}
		}

		// No usable answer is a non-decision, so it's retried rather than taken
		// for a clean skip. The vtxo is kept locked: it may well be spent, so it
		// must not be offered as an input, and no row at all would let a mailbox
		// replay store it spendable without ever asking the server. The body is
		// not validated here; the retry that gets its status does that before
		// the vtxo can become spendable.
		if !locked.is_empty() {
			warn!("Could not get the status of {} recovery vtxos, keeping them locked until \
				it is known", locked.len());
			self.store_vtxos(locked.iter(), &VtxoState::Locked { holder: None }).await?;
			for vtxo in &locked {
				report.push_failed(vtxo.id(), Some(vtxo.amount()));
			}
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
		let candidates = ids.into_iter().map(|id| (id, None)).collect();
		self.recover_candidates(&mut report, candidates, gap_limit).await?;
		Ok(report)
	}

	/// Ask the server for the VTXOs owned by the children of our VTXO xpub and
	/// recover each of them.
	///
	/// Unlike the mailbox scans this needs no backup posted by the old wallet
	/// and no gap limit: the server scans a fixed range of key indices per
	/// call, and we ask for the next range for as long as the server reports
	/// that more VTXOs may follow. Each VTXO comes with its body and spend
	/// state, so it needs no further request. Every index up to the highest
	/// one whose key matches its VTXO is stored as revealed, so the key lookups
	/// of later scans resolve from the database.
	///
	/// Returns `Ok(false)` when the server doesn't offer the rpc.
	async fn recover_from_xpub(&self, report: &mut RecoveryReport) -> anyhow::Result<bool> {
		let (mut srv, ark_info) = self.require_server().await?;
		let xpub = self.vtxo_xpub().encode().to_vec();

		let mut start_index = 0u32;
		loop {
			// Each request is signed anew, so a long scan never outlives its
			// authorization.
			let expiry = chrono::Local::now() + std::time::Duration::from_secs(60);
			let auth = XpubRecoveryAuthorization::new(
				&self.inner.seed.vtxo, ark_info.server_pubkey, expiry,
			);
			let req = protos::RecoverVtxosByXpubRequest {
				xpub: xpub.clone(),
				start_index,
				authorization: auth.serialize(),
			};
			let resp = match srv.client.recover_vtxos_by_xpub(req).await {
				Ok(resp) => resp.into_inner(),
				Err(status) if status.code() == tonic::Code::Unimplemented => {
					info!("Server doesn't support VTXO recovery by xpub: {}", status.message());
					return Ok(false);
				},
				Err(e) => return Err(e).context("error recovering vtxos by xpub"),
			};
			debug!("Server scanned {} xpub children from index {start_index} and returned {} vtxos",
				resp.nb_keys_scanned, resp.vtxos.len(),
			);

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
				if report.seen(vtxo.id()) {
					continue;
				}

				// The index is only trusted once it derives the key of the VTXO.
				let index = entry.derivation_index;
				if index >= NB_NORMAL_CHILDREN
					|| self.inner.seed.derive_vtxo_keypair(index).public_key() != vtxo.user_pubkey()
				{
					warn!("Recovery vtxo {} is not owned by key {index} of our xpub", vtxo.id());
					report.push_foreign(&vtxo);
					continue;
				}
				max_index = max_index.max(Some(index));

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
				self.reveal_vtxo_keys_up_to(max_index).await
					.context("failed to store recovered vtxo keys")?;
			}
			self.store_recovered_vtxos(report, vtxos).await?;

			// A server that scanned nothing would have us ask for the same
			// range forever.
			let end_index = start_index.saturating_add(resp.nb_keys_scanned);
			if !resp.have_more || end_index == start_index {
				break;
			}
			start_index = end_index;
		}
		Ok(true)
	}

	/// Store every VTXO key up to and including `index` as revealed.
	async fn reveal_vtxo_keys_up_to(&self, index: u32) -> anyhow::Result<()> {
		let mut next = self.inner.db.get_last_vtxo_key_index().await?.map(|i| i + 1).unwrap_or(0);
		while next <= index {
			let end = next.saturating_add(KEY_REVEAL_BATCH_SIZE).min(index + 1);
			let keys = (next..end)
				.map(|i| (i, self.inner.seed.derive_vtxo_keypair(i).public_key()))
				.collect::<Vec<_>>();
			self.inner.db.store_vtxo_keys(&keys).await?;
			next = end;
		}
		Ok(())
	}

	/// Rebuild the wallet's VTXO set from the server's xpub lookup, the
	/// seed-derived recovery mailbox and the arkoor messages in the regular
	/// mailbox.
	///
	/// The xpub lookup runs to its end before either mailbox is read. Both
	/// mailboxes are then read from checkpoint 0, and every VTXO they reference
	/// that the lookup didn't settle is resolved against the server, and against the chain when the server
	/// reports it spendable, one mailbox page at a time and stored accordingly.
	/// Returns a [`RecoveryReport`] (see it for why recovered/skipped/failed
	/// matters).
	pub(crate) async fn recover_from_seed(&self) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();
		let gap_limit = self.inner.config.vtxo_key_gap_limit;

		// The xpub lookup comes first: it needs no backup and no gap limit, and
		// it reveals every key up to its highest VTXO, so the mailbox scans find
		// their keys in the database. Its failure is reported at the end: the
		// mailboxes are still worth a try.
		let xpub_result = self.recover_from_xpub(&mut report).await;
		if let Err(e) = &xpub_result {
			warn!("VTXO recovery by xpub failed, continuing with the mailboxes: {:#}", e);
		}

		// A VTXO the lookup settled keeps the state it was given, so the server
		// is only asked about the VTXOs the lookup missed. One it failed on is
		// resolved again, by the mailbox scans or by the retries below.
		let mut seen = report.recovered.ids()
			.chain(report.skipped.ids())
			.chain(report.foreign.ids())
			.chain(report.exited.ids())
			.collect::<HashSet<_>>();

		// The regular mailbox comes next: its arkoor messages carry full vtxos,
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
				"Recovery found {} vtxo(s) not derivable from this seed within the \
				gap limit ({gap_limit}); if any are ours they were not recovered: {:?}",
				report.foreign.len(), report.foreign,
			);
		}

		// We retry 3 times to recover the failed VTXOs.
		for _ in 0..3 {
			if report.failed.is_empty() {
				break;
			}

			let candidates = report.failed.ids().map(|id| (id, None)).collect::<Vec<_>>();
			self.recover_candidates(&mut report, candidates, gap_limit).await?;
		}

		// Claim the outputs of the round participations recovery rebuilt.
		if let Err(e) = self.sync_pending_rounds().await {
			warn!("Error syncing recovered round participations: {:#}", e);
		}

		if report.is_complete() {
			info!(
				"Recovered {} spendable vtxos from the server and the recovery mailbox ({} skipped)",
				report.recovered.len(), report.skipped.len(),
			);
		} else if !report.failed.is_empty() {
			warn!(
				"Recovery incomplete: recovered {} spendable vtxos, but {} could not be \
				checked due to errors; funds may be missing — retry recovery to recover \
				them ({} skipped). Failed vtxos: {:?}",
				report.recovered.len(), report.failed.len(),
				report.skipped.len(), report.failed,
			);
		}

		xpub_result?;
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
			not_found: RecoveryReportEntry(HashMap::from([(dummy_id(3), None)])),
		};
		assert!(clean.is_complete(),
			"recovered, skipped and not found VTXOs are clean decisions, not failures");

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

