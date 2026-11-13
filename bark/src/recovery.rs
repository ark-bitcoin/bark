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
//! Recovery runs as a wallet action ([`crate::actions::recovery`]) that is
//! started when a wallet is created from a seed and resumed by every sync until
//! no VTXO is left undecided.
//!
//! Note that recovery is a trusted process. The server can withhold VTXOs
//! or may falsely represent spendable VTXOs as spent. Its word on the spend
//! state is final: a VTXO it reports spent is stored spent without being
//! validated, and only a VTXO it reports spendable is validated and checked
//! against the chain. Prefer to maintain back-ups and use recovery from the
//! mnemonic as a last resort.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Bound;

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::Keypair;
use log::{debug, info, trace, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use server_rpc::{protos, TryFromBytes, MAX_NB_VTXO_IDS};
use server_rpc::protos::VtxoSpendState;

use crate::Wallet;
use crate::actions::DriveMode;
use crate::actions::recovery::{
	recovery_lock_holder, Progress, Recovery, RecoveryMailbox, RECOVERY_ACTION_ID,
};
use crate::mailbox::{MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT};
use crate::vtxo::{
	ServerStatusAdoption, VtxoLockHolder, VtxoState, VtxoStateKind, VtxoValidationError, WalletVtxo,
};

/// How many answered attempts a VTXO gets before recovery gives up on it.
///
/// Only an attempt the server or the chain answered without deciding counts, so
/// an outage does not use it up. A drive makes up to four attempts per VTXO.
pub const MAX_RECOVERY_ATTEMPTS: u32 = 40;

/// VTXO ids, each with its amount when the body is known, ordered by id.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReportEntry(BTreeMap<VtxoId, Option<Amount>>);

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

	pub fn contains(&self, vtxo_id: VtxoId) -> bool {
		self.0.contains_key(&vtxo_id)
	}

	/// Up to `limit` ids that come after `after`, or from the first id when
	/// `after` is `None`, in id order.
	pub(crate) fn ids_after(&self, after: Option<VtxoId>, limit: usize) -> Vec<VtxoId> {
		let range = match after {
			Some(after) => self.0.range((Bound::Excluded(after), Bound::Unbounded)),
			None => self.0.range(..),
		};
		range.take(limit).map(|(id, _)| *id).collect()
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
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
	/// Spendable VTXOs that were successfully re-imported.
	recovered: RecoveryReportEntry,
	/// VTXOs deliberately left out: reported spent or still in-flight by the
	/// server, or invalid.
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
	/// VTXOs recovery gave up on after [`MAX_RECOVERY_ATTEMPTS`] failed attempts.
	/// One with a stored body stays locked, as it may be spent, and a later
	/// recovery tries it again.
	#[serde(default)]
	abandoned: RecoveryReportEntry,
	/// The failed attempts so far of each VTXO in `failed`.
	#[serde(default)]
	attempts: BTreeMap<VtxoId, u32>,
}

impl RecoveryReport {
	/// Whether the scan accounted for every VTXO in the mailbox.
	///
	/// A `failed`, `abandoned` or `foreign` VTXO means funds may be missing, so
	/// none may be present. `failed` is retryable; a `foreign` id instead needs a
	/// wider gap limit to be matched.
	pub fn is_complete(&self) -> bool {
		self.failed.is_empty() && self.abandoned.is_empty() && self.foreign.is_empty()
	}

	/// Whether the VTXO is in any entry of the report.
	pub fn contains(&self, vtxo_id: VtxoId) -> bool {
		self.recovered.contains(vtxo_id) || self.skipped.contains(vtxo_id) ||
			self.failed.contains(vtxo_id) || self.foreign.contains(vtxo_id) ||
			self.exited.contains(vtxo_id) || self.not_found.contains(vtxo_id) ||
			self.abandoned.contains(vtxo_id)
	}

	pub fn recovered(&self) -> &RecoveryReportEntry {
		&self.recovered
	}

	pub fn push_recovered<G>(&mut self, vtxo: &Vtxo<G>) {
		self.clear_failed(vtxo.id());
		self.recovered.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn skipped(&self) -> &RecoveryReportEntry {
		&self.skipped
	}

	pub fn push_skipped<G>(&mut self, vtxo: &Vtxo<G>) {
		self.clear_failed(vtxo.id());
		self.skipped.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn foreign(&self) -> &RecoveryReportEntry {
		&self.foreign
	}

	pub fn push_foreign<G>(&mut self, vtxo: &Vtxo<G>) {
		self.clear_failed(vtxo.id());
		self.foreign.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn failed(&self) -> &RecoveryReportEntry {
		&self.failed
	}

	/// A VTXO failed without a known body first learns its amount once a later
	/// attempt fetches the body.
	pub fn push_failed(&mut self, id: VtxoId, amount: Option<Amount>) {
		match amount {
			Some(amount) => { self.failed.0.insert(id, Some(amount)); },
			None => self.failed.insert(id, None),
		}
	}

	/// Report a failed attempt the server or the chain answered without
	/// deciding on the VTXO. After [`MAX_RECOVERY_ATTEMPTS`] of them the VTXO is
	/// abandoned instead.
	pub fn push_failed_attempt(&mut self, id: VtxoId, amount: Option<Amount>) {
		let attempts = self.attempts.entry(id).or_default();
		*attempts += 1;
		if *attempts < MAX_RECOVERY_ATTEMPTS {
			self.push_failed(id, amount);
			return;
		}
		let amount = amount.or(self.failed.0.get(&id).copied().flatten());
		self.clear_failed(id);
		self.abandoned.insert(id, amount);
	}

	pub fn abandoned(&self) -> &RecoveryReportEntry {
		&self.abandoned
	}

	fn clear_failed(&mut self, id: VtxoId) {
		self.failed.remove(id);
		self.attempts.remove(&id);
	}

	pub fn exited(&self) -> &RecoveryReportEntry {
		&self.exited
	}

	pub fn push_exited<G>(&mut self, vtxo: &Vtxo<G>) {
		self.clear_failed(vtxo.id());
		self.exited.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn not_found(&self) -> &RecoveryReportEntry {
		&self.not_found
	}

	pub fn push_not_found(&mut self, id: VtxoId) {
		self.clear_failed(id);
		self.not_found.insert(id, None);
	}

	/// Report a VTXO the wallet already holds by the state it is in.
	pub fn push_decided(&mut self, stored: &WalletVtxo) {
		let id = stored.vtxo.id();
		let amount = Some(stored.vtxo.amount());
		self.clear_failed(id);
		match stored.state {
			VtxoState::Spendable => self.recovered.insert(id, amount),
			VtxoState::Exited => self.exited.insert(id, amount),
			VtxoState::Locked { .. } | VtxoState::Spent => self.skipped.insert(id, amount),
		}
	}
}

/// Outcome of the recovery scan on wallet open.
///
/// [`crate::OpenWalletArgs::on_recovery_finished`] is called exactly once per
/// successful open, with one of these. A caller never has to read meaning into
/// the callback staying silent: not running and failing are both stated.
#[derive(Debug)]
pub enum RecoveryStatus {
	/// No scan was attempted: the wallet already existed without a recovery in
	/// progress, or the caller set [`crate::OpenWalletArgs::skip_recovery`].
	NotRun,
	/// The recovery could not be started or its state could not be read back.
	/// Nothing is known about the mailbox's VTXOs, so funds may be missing.
	Failed(anyhow::Error),
	/// The recovery stopped before it was done, on an error or on VTXOs it could
	/// not decide on yet. The report holds what it decided so far; its failed
	/// VTXOs are kept locked. Every sync resumes the recovery from where it
	/// stopped, see [`Wallet::pending_recovery`].
	InProgress(RecoveryReport),
	/// The recovery is done: no VTXO is left failed. Check
	/// [`RecoveryReport::is_complete`]: a VTXO whose key is beyond the gap limit
	/// can still be unaccounted for.
	Completed(RecoveryReport),
}

impl Wallet {
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
	/// Returns the fetched VTXOs, the ids the server does not know, and the ids
	/// whose batch the server answered. An id whose batch request failed is in
	/// none of them. Only a server that cannot be reached is an error.
	pub(crate) async fn fetch_vtxos(
		&self,
		ids: &[VtxoId],
	) -> anyhow::Result<(HashMap<VtxoId, Vtxo<Full>>, HashSet<VtxoId>, HashSet<VtxoId>)> {
		let mut ret = HashMap::with_capacity(ids.len());
		let mut missing = HashSet::new();
		let mut answered = HashSet::new();
		if ids.is_empty() {
			return Ok((ret, missing, answered));
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
			answered.extend(chunk.iter().copied());

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

		Ok((ret, missing, answered))
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

	/// Stage a set of recovery candidates: fetch the bodies the mailbox did not
	/// carry, check we own them, and store the owned ones locked by `holder` until
	/// [`Wallet::settle_recovery_vtxos`] decides on them.
	///
	/// A candidate's body is given when the mailbox message carried one;
	/// otherwise it is fetched from the server. A body the mailbox carried is
	/// validated before it is stored: an invalid one is dropped and reported
	/// skipped.
	///
	/// A candidate already stored locked by `holder` was staged by an earlier
	/// attempt, so its stored body is used. A candidate the wallet holds in any
	/// other state was decided before, and is only reported.
	///
	/// Returns every staged VTXO with its keypair. Each one is reported failed
	/// until it is settled.
	pub(crate) async fn stage_recovery_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<(VtxoId, Option<Vtxo<Full>>)>,
		gap_limit: u32,
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<Vec<(Vtxo<Full>, Keypair)>> {
		// A repeated id finds its fetched body already taken and would be
		// reported failed.
		let mut seen = HashSet::new();
		let candidates = candidates.into_iter()
			.filter(|(id, _)| seen.insert(*id))
			.collect::<Vec<_>>();

		let staged_state = VtxoState::Locked { holder: holder.clone() };
		let mut staged_ids = Vec::new();
		let mut unknown = Vec::new();
		for (id, vtxo) in candidates {
			match self.inner.db.get_wallet_vtxo(id).await? {
				Some(stored) if stored.state == staged_state => staged_ids.push(id),
				Some(stored) => report.push_decided(&stored),
				None => unknown.push((id, vtxo)),
			}
		}

		// A body the mailbox carried is only as good as its relay, so it is
		// checked before it is stored. A body the server gives is checked once
		// the server reports it spendable.
		let mut checked = Vec::with_capacity(unknown.len());
		for (id, vtxo) in unknown {
			if let Some(vtxo) = &vtxo {
				if let Err(VtxoValidationError::Invalid(e)) = self.validate_vtxo(vtxo).await {
					warn!("Recovery vtxo {id} from the mailbox is invalid, skipping: {e}");
					report.push_skipped(vtxo);
					continue;
				}
			}
			checked.push((id, vtxo));
		}
		let unknown = checked;

		let to_fetch = unknown.iter()
			.filter(|(_, vtxo)| vtxo.is_none())
			.map(|(id, _)| *id)
			.collect::<Vec<_>>();
		let (mut fetched, missing, answered) = self.fetch_vtxos(&to_fetch).await?;

		let mut new = Vec::with_capacity(unknown.len());
		for (id, vtxo) in unknown {
			// The fetch logged why the body is missing.
			match vtxo.or_else(|| fetched.remove(&id)) {
				Some(vtxo) => new.push(vtxo),
				None if missing.contains(&id) => report.push_not_found(id),
				None if answered.contains(&id) => report.push_failed_attempt(id, None),
				None => report.push_failed(id, None),
			}
		}

		// One key scan for the whole batch. [`Wallet::find_vtxo_keypairs`] widens
		// its window on every match, so later keys of the batch are found however
		// the candidates are ordered. The keys of staged VTXOs are on record.
		let staged = self.get_full_vtxos(&staged_ids).await?;
		let pubkeys = staged.iter().chain(&new).map(|v| v.user_pubkey()).collect::<Vec<_>>();
		let keypairs = self.find_vtxo_keypairs(pubkeys, gap_limit).await?;

		let mut owned = Vec::with_capacity(new.len());
		for vtxo in new {
			match keypairs.get(&vtxo.user_pubkey()) {
				Some(_) => owned.push(vtxo),
				None => report.push_foreign(&vtxo),
			}
		}

		// The locked row keeps the VTXO out of the spendable set until the server
		// has spoken, and lets a later attempt pick it up without asking the
		// mailbox again.
		if !owned.is_empty() {
			// Some backends overwrite a row on store, so a VTXO an arkoor receive
			// stored since the check above is left as it is. The receive takes the
			// same lock around its own check and store.
			let _mailbox = self.inner.lock_manager.lock(
				MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
			).await.context("failed to acquire mailbox processing lock")?;
			let mut unstored = Vec::with_capacity(owned.len());
			for vtxo in owned {
				match self.inner.db.get_wallet_vtxo(vtxo.id()).await? {
					Some(stored) => report.push_decided(&stored),
					None => unstored.push(vtxo),
				}
			}
			owned = unstored;
			if !owned.is_empty() {
				self.store_vtxos(owned.iter(), &staged_state).await?;
			}
		}

		let mut ret = Vec::with_capacity(staged.len() + owned.len());
		for vtxo in staged.into_iter().chain(owned) {
			let Some(keypair) = keypairs.get(&vtxo.user_pubkey()) else {
				warn!("Staged recovery vtxo {} has no key on record", vtxo.id());
				report.push_failed_attempt(vtxo.id(), Some(vtxo.amount()));
				continue;
			};
			report.push_failed(vtxo.id(), Some(vtxo.amount()));
			ret.push((vtxo, *keypair));
		}
		Ok(ret)
	}

	/// Ask the server for the status of staged recovery VTXOs and move each one
	/// out of its lock accordingly, see [`Wallet::store_recovered_vtxos`].
	///
	/// A VTXO without an answer, or whose validation fails on the chain, stays
	/// locked and reported failed: it may well be spent, so it must not be offered
	/// as an input. One the server or the chain answered for is abandoned after
	/// [`MAX_RECOVERY_ATTEMPTS`] such failures. An invalid VTXO is dropped and
	/// reported skipped.
	pub(crate) async fn settle_recovery_vtxos(
		&self,
		report: &mut RecoveryReport,
		staged: Vec<(Vtxo<Full>, Keypair)>,
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		// The server is the authority on whether a vtxo was spent elsewhere,
		// and recovery has nothing else to go on.
		let queries = staged.iter().map(|(vtxo, keypair)| (vtxo.id(), keypair)).collect::<Vec<_>>();
		let (states, foreign, answered) = self.fetch_own_vtxo_spend_states(&queries).await?;
		let foreign = foreign.into_iter().collect::<HashSet<_>>();

		// A VTXO whose batch got no answer stays staged, and the attempt doesn't
		// count against its budget.
		let mut vtxos = Vec::with_capacity(staged.len());
		for (vtxo, _) in staged {
			if foreign.contains(&vtxo.id()) {
				warn!("Recovery vtxo {} has the owner mailbox of another wallet", vtxo.id());
				self.inner.db.remove_vtxo(vtxo.id()).await
					.context("failed to drop foreign recovery VTXO")?;
				report.push_foreign(&vtxo);
				continue;
			}
			if !answered.contains(&vtxo.id()) {
				report.push_failed(vtxo.id(), Some(vtxo.amount()));
				continue;
			}
			// The fetch logged why an answer is missing.
			let adoption = match states.get(&vtxo.id()) {
				Some(state) => ServerStatusAdoption::from_spend_state(*state),
				None => Err(anyhow::anyhow!("no usable answer from the server")),
			};
			vtxos.push((vtxo, adoption));
		}
		self.store_recovered_vtxos(report, vtxos, holder).await
	}

	/// Store owned VTXOs in the state the server reported for them.
	///
	/// The server's word on the spend state is final, so it is taken before any
	/// chain lookup: a VTXO it reports spent is stored spent as is, and only a
	/// VTXO it reports spendable is validated and checked for an exit. Rows are
	/// written once per state, not once per VTXO, and move a VTXO staged locked by
	/// `holder` to that state. An error leaves every VTXO not yet stored in
	/// its state as it was.
	pub(crate) async fn store_recovered_vtxos(
		&self,
		report: &mut RecoveryReport,
		vtxos: Vec<(Vtxo<Full>, anyhow::Result<ServerStatusAdoption>)>,
		holder: &Option<VtxoLockHolder>,
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
				// belongs, so nothing is kept. Arkoor mailbox messages only carry
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
		// vtxo as spendable again. A staged row, or one from an earlier, failed
		// attempt, is forced along.
		if !spent.is_empty() {
			self.store_vtxos(spent.iter(), &VtxoState::Spent).await?;
			self.mark_vtxos_as_spent(spent.iter().map(|v| v.id())).await?;
			for vtxo in &spent {
				debug!("Recovery vtxo {} already spent, skipping", vtxo.id());
				report.push_skipped(vtxo);
			}
			self.record_expiry_payouts(spent.iter().map(|v| v.id())).await;
		}

		// An unclaimed output of a delegated round participation lacks its
		// unlock preimage, so it can't validate yet. The participation is
		// rebuilt instead, and the round sync claims the output. Its staged row
		// is dropped so that releasing the lock can't make it spendable.
		for vtxo in unclaimed {
			let id = vtxo.id();
			let unlock_hash = vtxo.unlock_hash().expect("checked above");
			match self.recover_delegated_participation(unlock_hash).await {
				Ok(()) => {
					debug!("Recovery vtxo {id} is an unclaimed round output, left to the round sync");
					self.inner.db.remove_vtxo(id).await
						.context("Failed to drop unclaimed recovery vtxo")?;
					report.push_skipped(&vtxo);
				},
				Err(e) => {
					warn!("Could not recover the round participation of vtxo {id}: {:#}", e);
					report.push_failed_attempt(id, Some(vtxo.amount()));
				},
			}
		}

		// Only a vtxo the server lets us spend is worth the chain lookups.
		let mut recovered = Vec::with_capacity(spendable.len());
		for vtxo in spendable {
			match self.validate_vtxo(&vtxo).await {
				Ok(()) => {},
				// An invalid body stays invalid, so it is a decision: the staged row
				// is dropped so that releasing the lock can't make it spendable.
				Err(VtxoValidationError::Invalid(e)) => {
					warn!("Recovery VTXO {} is invalid, skipping: {}", vtxo.id(), e);
					self.inner.db.remove_vtxo(vtxo.id()).await
						.context("Failed to drop invalid recovery VTXO")?;
					report.push_skipped(&vtxo);
					continue;
				},
				// A chain error or an anchor not yet visible is a non-decision, so
				// it is a failure, not a clean skip. Only an anchor the chain
				// answered for counts against the budget.
				Err(VtxoValidationError::Chain(e)) => {
					warn!("Could not validate recovery VTXO {}: {:#}", vtxo.id(), e);
					report.push_failed(vtxo.id(), Some(vtxo.amount()));
					continue;
				},
				Err(e) => {
					warn!("Could not validate recovery VTXO {}: {:#}", vtxo.id(), e);
					report.push_failed_attempt(vtxo.id(), Some(vtxo.amount()));
					continue;
				},
			}
			if self.check_vtxo_onchain_status(report, &vtxo).await? {
				continue;
			}
			recovered.push(vtxo);
		}
		// NB we don't use store_spendable_vtxos to avoid posting the vtxos again
		if !recovered.is_empty() {
			self.store_vtxos(recovered.iter(), &VtxoState::Spendable).await?;
			// Some backends keep the state of a row that exists on store, so the
			// staged lock is released here.
			self.unlock_vtxos(recovered.iter(), holder.clone()).await?;
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
			self.store_vtxos(locked.iter(), &VtxoState::Locked { holder: holder.clone() }).await?;
			for vtxo in &locked {
				report.push_failed_attempt(vtxo.id(), Some(vtxo.amount()));
			}
		}

		Ok(())
	}

	/// Recover a set of VTXOs: stage them, then settle them.
	///
	/// See [`Wallet::stage_recovery_candidates`] and
	/// [`Wallet::settle_recovery_vtxos`].
	pub(crate) async fn recover_candidates(
		&self,
		report: &mut RecoveryReport,
		candidates: Vec<(VtxoId, Option<Vtxo<Full>>)>,
		gap_limit: u32,
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let staged = self.stage_recovery_candidates(report, candidates, gap_limit, holder).await?;
		self.settle_recovery_vtxos(report, staged, holder).await
	}

	/// The report of the last recovery that finished in this process, if it was
	/// not taken yet.
	fn take_finished_recovery(&self) -> Option<RecoveryReport> {
		self.inner.finished_recovery.lock().take()
	}

	/// Recover the given VTXOs into this wallet's spendable set.
	///
	/// `gap_limit` overrides [`crate::Config::vtxo_key_gap_limit`] for the key
	/// scan that decides which of `ids` this wallet owns.
	///
	/// A VTXO an earlier recovery left locked is tried again, whether that was
	/// a call of this method or a recovery from seed that gave up on it.
	///
	/// Fails while a recovery from seed is being driven: both work on the same
	/// locked VTXOs.
	pub async fn recover_vtxos(
		&self,
		ids: impl IntoIterator<Item = VtxoId>,
		gap_limit: Option<u32>,
	) -> anyhow::Result<RecoveryReport> {
		let _recovery = self.try_lock_action::<Recovery>(&RECOVERY_ACTION_ID.to_string()).await?
			.context("a recovery from seed is running, try again once it is done")?;

		let ids = ids.into_iter().collect::<Vec<_>>();
		let holder = Some(recovery_lock_holder());
		self.adopt_unheld_recovery_locks(&ids, &holder).await?;

		let mut report = RecoveryReport::default();
		let gap_limit = gap_limit.unwrap_or(self.inner.config.vtxo_key_gap_limit);
		let candidates = ids.into_iter().map(|id| (id, None)).collect();
		self.recover_candidates(&mut report, candidates, gap_limit, &holder).await?;
		Ok(report)
	}

	/// Move every VTXO of `ids` that is locked without a holder under `holder`.
	///
	/// Earlier versions kept a VTXO whose status the server did not give locked
	/// without a holder. Such a VTXO is retried like one staged by `holder`.
	async fn adopt_unheld_recovery_locks(
		&self,
		ids: &[VtxoId],
		holder: &Option<VtxoLockHolder>,
	) -> anyhow::Result<()> {
		let unheld = VtxoState::Locked { holder: None };
		let mut adopted = Vec::new();
		for id in ids {
			match self.inner.db.get_wallet_vtxo(*id).await? {
				Some(stored) if stored.state == unheld => adopted.push(*id),
				_ => {},
			}
		}
		if adopted.is_empty() {
			return Ok(());
		}
		debug!("Retrying {} recovery vtxos locked without a holder", adopted.len());
		self.set_vtxo_states(
			adopted, &VtxoState::Locked { holder: holder.clone() }, &[VtxoStateKind::Locked],
		).await.context("failed to take over recovery vtxos locked without a holder")
	}

	/// The recovery from seed in progress, if any.
	///
	/// Its report's failed VTXOs are the ones still missing: they are kept locked
	/// until the server gives their status.
	pub async fn pending_recovery(&self) -> anyhow::Result<Option<Recovery>> {
		Ok(self.inner.db.get_wallet_action_checkpoint(&RECOVERY_ACTION_ID.to_string()).await?
			.and_then(|cp| cp.into_recovery()))
	}

	/// Whether the recovery from seed in progress has yet to read the regular
	/// mailbox, where the wallet's received arkoor packages are.
	pub(crate) async fn recovery_reads_regular_mailbox(&self) -> anyhow::Result<bool> {
		Ok(matches!(
			self.pending_recovery().await?.map(|r| r.progress),
			Some(Progress::Xpub { .. } | Progress::Scanning { mailbox: RecoveryMailbox::Regular, .. }),
		))
	}

	/// Drive the recovery from seed in progress, if any, until it is done or
	/// parks again.
	///
	/// Does nothing while another drive of the recovery holds its lock.
	pub async fn sync_pending_recovery(&self) -> anyhow::Result<()> {
		// The checkpoint is read under the lock: one read before it could be
		// the state of a drive that has since moved on or finished, and
		// driving it would bring that recovery back.
		let id = RECOVERY_ACTION_ID.to_string();
		let Some(checkpoint) = self.try_lock_action::<Recovery>(&id).await? else {
			trace!("Recovery from seed is already being driven, skipping");
			return Ok(());
		};
		let Some(recovery) = checkpoint.get() else {
			return Ok(());
		};
		info!("Resuming recovery from seed ({} vtxos still missing)",
			recovery.report.failed().len());
		self.drive_checkpoint(checkpoint, DriveMode::UntilParkOrDone).await
	}

	/// Rebuild the wallet's VTXO set from the server's xpub lookup, the
	/// seed-derived recovery mailbox and the arkoor messages in the regular
	/// mailbox.
	///
	/// The recovery is checkpointed before anything is read, then driven until it
	/// is done or parks. A recovery that is not done when this returns is resumed
	/// by every sync. A wallet runs at most one recovery: a recovery already in
	/// progress is driven instead of a new one.
	pub(crate) async fn start_recovery(&self) -> RecoveryStatus {
		let id = RECOVERY_ACTION_ID.to_string();
		let mut checkpoint = match self.try_lock_action::<Recovery>(&id).await {
			Ok(Some(checkpoint)) => checkpoint,
			Ok(None) => return RecoveryStatus::Failed(
				anyhow::anyhow!("a recovery from seed is already running"),
			),
			Err(e) => return RecoveryStatus::Failed(e),
		};

		if checkpoint.get().is_some() {
			warn!("A recovery from seed is already in progress, resuming it");
		} else {
			let recovery = Recovery::new(self.inner.config.vtxo_key_gap_limit);
			// An arkoor receive stores its package before the recovery exists, or
			// sees the recovery and leaves the package to it.
			let _mailbox = match self.inner.lock_manager.lock(
				MAILBOX_PROCESSING_LOCK_KEY, MAILBOX_PROCESSING_LOCK_TIMEOUT,
			).await {
				Ok(guard) => guard,
				Err(e) => return RecoveryStatus::Failed(
					e.context("failed to acquire mailbox processing lock"),
				),
			};
			if let Err(e) = checkpoint.create(self, recovery).await {
				return RecoveryStatus::Failed(e);
			}
		}

		let drive = self.drive_checkpoint(checkpoint, DriveMode::UntilParkOrDone);
		if let Err(e) = drive.await {
			warn!("Recovery from seed stopped before it was done; it resumes on the next \
				sync: {:#}", e);
		}

		match self.pending_recovery().await {
			Ok(Some(recovery)) => RecoveryStatus::InProgress(recovery.report),
			Ok(None) => RecoveryStatus::Completed(self.take_finished_recovery().unwrap_or_default()),
			Err(e) => RecoveryStatus::Failed(e),
		}
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
			recovered: RecoveryReportEntry(BTreeMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			skipped: RecoveryReportEntry(BTreeMap::from([(dummy_id(1), Some(Amount::from_sat(1000)))])),
			foreign: RecoveryReportEntry(BTreeMap::new()),
			failed: RecoveryReportEntry(BTreeMap::new()),
			exited: RecoveryReportEntry(BTreeMap::new()),
			not_found: RecoveryReportEntry(BTreeMap::from([(dummy_id(3), None)])),
			abandoned: RecoveryReportEntry(BTreeMap::new()),
			attempts: BTreeMap::new(),
		};
		assert!(clean.is_complete(),
			"recovered, skipped and not found VTXOs are clean decisions, not failures");

		assert!(RecoveryReport::default().is_complete(),
			"an empty report is trivially complete");
		assert!(!RecoveryReport {
			failed: RecoveryReportEntry(BTreeMap::from([(dummy_id(0), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a failed VTXO means recovery is incomplete");
		assert!(!RecoveryReport {
			foreign: RecoveryReportEntry(BTreeMap::from([(dummy_id(2), Some(Amount::from_sat(1000)))])),
			..Default::default()
		}.is_complete(), "a foreign id is likely an owned VTXO beyond the gap limit, so recovery is incomplete");
	}

	/// A VTXO is abandoned once its failed attempts reach the budget, and a
	/// decision before that resets its count.
	#[test]
	fn recovery_report_abandons_after_max_attempts() {
		let amount = Some(Amount::from_sat(1000));
		let mut report = RecoveryReport::default();
		for _ in 1..MAX_RECOVERY_ATTEMPTS {
			report.push_failed_attempt(dummy_id(0), amount);
		}
		assert!(report.failed().contains(dummy_id(0)), "below the budget the VTXO is failed");

		report.push_failed_attempt(dummy_id(0), None);
		assert!(!report.failed().contains(dummy_id(0)), "an abandoned VTXO is not failed");
		assert_eq!(report.abandoned().0.get(&dummy_id(0)), Some(&amount),
			"the abandoned VTXO keeps the amount it was failed with");
		assert!(report.contains(dummy_id(0)), "scans must skip an abandoned VTXO");
		assert!(!report.is_complete(), "an abandoned VTXO means funds may be missing");

		for _ in 1..MAX_RECOVERY_ATTEMPTS {
			report.push_failed_attempt(dummy_id(1), amount);
		}
		report.clear_failed(dummy_id(1));
		report.push_failed_attempt(dummy_id(1), amount);
		assert!(report.failed().contains(dummy_id(1)), "a decision resets the attempt count");
	}
}

