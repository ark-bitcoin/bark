//! Wallet recovery from seed.
//!
//! As a wallet creates or receives VTXOs it posts their ids to a mailbox keyed
//! by a dedicated, seed-derived recovery key (see
//! [`Wallet::post_recovery_vtxo_ids`]). Recovering the seed re-derives that key
//! and reads back every posted id to rebuild the spendable VTXO set.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Context;
use bitcoin::Amount;
use bitcoin::secp256k1::{Keypair, PublicKey};
use log::{debug, info, warn};

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::attestations::VtxoStatusAttestation;
use ark::mailbox::MailboxAuthorization;
use ark::vtxo::Full;
use bitcoin_ext::BlockHeight;
use server_rpc::TryFromBytes;
use server_rpc::protos::{self, VtxoSpendState};
use server_rpc::protos::mailbox_server::mailbox_message::Message;

use crate::Wallet;
use crate::vtxo::VtxoState;

/// Consecutive unused key indices we tolerate before concluding a VTXO isn't ours.
const STOP_GAP: u32 = 50;

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

/// Summary of a recovery scan over the seed-derived recovery mailbox.
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
	/// VTXOs deliberately left out: spent into a newer recovered VTXO, exited
	/// on-chain, or reported non-spendable by the server.
	skipped: RecoveryReportEntry,
	/// VTXOs we could not decide on due to an error (fetch, validation, or no
	/// usable spend state). Not known to be spent, so funds may be missing.
	failed: RecoveryReportEntry,
	/// VTXOs found in the mailbox whose key we could not derive within the gap
	/// limit. Only the seed owner can post here, so these are most likely our own
	/// VTXOs whose key sits beyond [`STOP_GAP`]; their presence means funds may be
	/// missing and the scan can't be reported complete.
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

	pub fn push_recovered(&mut self, vtxo: &Vtxo<Full>) {
		self.failed.remove(vtxo.id());
		self.recovered.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn skipped(&self) -> &RecoveryReportEntry {
		&self.skipped
	}

	pub fn push_skipped(&mut self, vtxo: &Vtxo<Full>) {
		self.failed.remove(vtxo.id());
		self.skipped.insert(vtxo.id(), Some(vtxo.amount()));
	}

	pub fn foreign(&self) -> &RecoveryReportEntry {
		&self.foreign
	}

	pub fn push_foreign(&mut self, vtxo: &Vtxo<Full>) {
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

	pub fn push_exited(&mut self, vtxo: &Vtxo<Full>) {
		self.failed.remove(vtxo.id());
		self.exited.insert(vtxo.id(), Some(vtxo.amount()));
	}
}

/// A recovered VTXO paired with the key that proves we own it.
///
/// The pairing invariant — `keypair` is `vtxo`'s owner key — is enforced by
/// [`OwnedVtxo::new`], so the rest of recovery can rely on it.
pub(crate) struct OwnedVtxo {
	vtxo: Vtxo<Full>,
	keypair: Keypair,
}

impl OwnedVtxo {
	/// Pair a VTXO with its owner keypair. The sole constructor, so the
	/// `keypair`-owns-`vtxo` invariant holds everywhere [`OwnedVtxo`] is used.
	fn new(vtxo: Vtxo<Full>, keypair: Keypair) -> Self {
		debug_assert_eq!(
			vtxo.user_pubkey(), keypair.public_key(),
			"OwnedVtxo keypair must match the VTXO's owner pubkey",
		);
		OwnedVtxo { vtxo, keypair }
	}
}

/// Ordering key for recovered VTXOs: ascending by expiry height, then arkoor
/// chain length ([`Vtxo::exit_depth`]).
///
/// Expiry is inherited within an arkoor chain, so `exit_depth` breaks the tie,
/// ordering ancestors before descendants. [`Wallet::recover_from_mailbox`]
/// walks the sorted set in reverse (descendants first) so a VTXO spent into a
/// newer one is seen as already-spent and skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ChainOrder {
	expiry: BlockHeight,
	depth: u16,
}

impl ChainOrder {
	fn of(vtxo: &Vtxo<Full>) -> Self {
		ChainOrder { expiry: vtxo.expiry_height(), depth: vtxo.exit_depth() }
	}
}

impl Wallet {
	fn mailbox_request(&self, checkpoint: u64) -> protos::mailbox_server::MailboxRequest {
		let expiry = chrono::Local::now() + std::time::Duration::from_secs(60);
		let auth = MailboxAuthorization::new(&self.recovery_mailbox_keypair(), expiry);
		let mailbox_id = auth.mailbox();

		protos::mailbox_server::MailboxRequest {
			mailbox_id: mailbox_id.serialize(),
			authorization: Some(auth.serialize()),
			checkpoint,
		}
	}

	async fn fetch_valid_owned_vtxos(&self, report: &mut RecoveryReport, ids: &[VtxoId]) ->
		anyhow::Result<Vec<OwnedVtxo>>
	{
		// Drain the whole mailbox into a candidate set. The mailbox isn't
		// de-duplicated, so track the ids we've fetched and skip any repeats.
		let mut candidates = HashMap::new();

		for id in ids {
			match self.fetch_vtxo(*id).await {
				Ok(vtxo) => {
					candidates.insert(*id, vtxo);
				},
				Err(e) => {
					warn!("Could not fetch recovery vtxo {id}: {:#}", e);
					report.push_failed(*id, None);
				}
			}
		}

		// Resolve ownership over the complete candidate set in one pass.
		let candidates = candidates.into_values().collect();
		let owned = self.resolve_owned_vtxos(candidates, report).await?;

		// Order by (expiry, arkoor chain length) so the caller can walk newest-first.
		let mut vtxos = BTreeMap::<ChainOrder, Vec<OwnedVtxo>>::new();
		for owned in owned {
			vtxos.entry(ChainOrder::of(&owned.vtxo)).or_default().push(owned);
		}

		Ok(vtxos.into_values().flatten().collect())
	}


	/// Page the recovery mailbox and collect the distinct VTXO ids it references.
	///
	/// Reads the whole mailbox from checkpoint 0 (independent of the regular
	/// mailbox checkpoint), taking ids from `RecoveryVtxoIds` and `Arkoor`
	/// messages and de-duplicating them into a `HashSet`. Fetching the VTXOs,
	/// validating them, resolving ownership, and ordering are left to the caller.
	async fn read_mailbox_recovery_vtxo_ids(&self) -> anyhow::Result<(HashSet<VtxoId>, u64)> {
		let (mut srv, _) = self.require_server().await?;

		// Drain the whole mailbox into a candidate set. The mailbox isn't
		// de-duplicated, so track the ids we've fetched and skip any repeats.
		let mut ids = HashSet::new();

		let mut iteration = 0;
		let mut checkpoint = 0u64;
		loop {
			iteration += 1;

			let req = self.mailbox_request(checkpoint);
			let resp = srv.mailbox_client.read_mailbox(req).await
				.context("error reading recovery mailbox")?.into_inner();

			debug!("Recovery mailbox returned {} messages on iteration {iteration}", resp.messages.len());

			let prev_checkpoint = checkpoint;
			for msg in &resp.messages {
				match &msg.message {
					Some(Message::RecoveryVtxoIds(m)) => {
						checkpoint = checkpoint.max(msg.checkpoint);
						for raw in &m.vtxo_ids {
							let Ok(id) = VtxoId::from_bytes(raw.clone()) else {
								warn!("Ignoring undecodable recovery vtxo id: {raw:?}");
								continue;
							};
							ids.insert(id);
						}
					},
					Some(Message::Arkoor(m)) => {
						checkpoint = checkpoint.max(msg.checkpoint);
						for raw in &m.vtxos {
							let Ok(vtxo) = Vtxo::<Full>::from_bytes(raw.clone()) else {
								warn!("Ignoring undecodable vtxo: {raw:?}");
								continue;
							};
							ids.insert(vtxo.id());
						}
					},
					Some(Message::RoundParticipationCompleted(_)) |
					Some(Message::IncomingLightningPayment(_)) |
					Some(Message::LightningSendFinished(_)) => {},
					None => {
						warn!("Recovery mailbox returned a message with no content: {msg:?}");
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
				warn!("Recovery mailbox iteration {iteration} made no progress \
					at checkpoint {checkpoint}; stopping");
				break;
			}
		}

		Ok((ids, checkpoint))
	}

	/// Fetch the full [`Vtxo<Full>`] for `id` from the server.
	///
	/// The recovery mailbox only stores ids, so we ask the server for the full
	/// VTXO data. The result is untrusted until validated by the caller.
	async fn fetch_vtxo(&self, id: VtxoId) -> anyhow::Result<Vtxo<Full>> {
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
	async fn check_vtxo_onchain_status(&self, report: &mut RecoveryReport, vtxo: &Vtxo<Full>) -> anyhow::Result<bool> {
		// An off-chain VTXO's tx is only confirmed once it has been exited,
		// so if we see it on-chain the funds live in the on-chain wallet and
		// it must not be recovered as spendable. The server's spend status
		// doesn't capture unilateral exits, so we check the chain ourselves.
		match self.inner.chain.tx_confirmed(vtxo.point().txid).await {
			Ok(Some(height)) => {
				self.store_vtxos(&vec![vtxo.clone()], &VtxoState::Exited).await?;
				self.exit_mgr().start_exit_for_vtxos_including_non_standard(&vec![vtxo.to_bare()]).await?;
				report.push_exited(vtxo);
				debug!("Skipping recovery vtxo {}: confirmed on-chain at height {height} (exited)", vtxo.id());
				Ok(true)
			},
			// If we could not confirm the exit status, we consider it is not exited yet.
			// If it actually is, next wallet sync will handle it properly
			Ok(None) | Err(_) => Ok(false),
		}
	}

	/// Query the server for `id`'s spend state.
	///
	/// `keypair` is the VTXO's owner key, used to build the attestation that
	/// proves to the server we control the VTXO (required by the endpoint).
	async fn check_vtxo_server_status(
		&self,
		report: &mut RecoveryReport,
		vtxo: &Vtxo<Full>,
		keypair: &Keypair,
	) -> anyhow::Result<bool> {
		let (mut srv, _) = self.require_server().await?;
		let vtxo_id = vtxo.id();
		let attestation = VtxoStatusAttestation::new(vtxo_id, keypair);
		let resp = srv.client.get_vtxo_status(protos::GetVtxoStatusRequest {
			vtxo_id: vtxo_id.to_bytes().to_vec(),
			attestation: attestation.serialize(),
		}).await.with_context(|| format!("error fetching status for vtxo {vtxo_id}"))?.into_inner();

		let spend_state = protos::VtxoSpendState::try_from(resp.spend_state)
			.map_err(|_| anyhow::anyhow!(
				"server returned unknown spend state {} for vtxo {vtxo_id}", resp.spend_state,
			));

		// The server is the authority on whether it was spent elsewhere.
		// Matched exhaustively (no catch-all) so a new spend state forces an
		// explicit decision rather than being silently skipped.
		match spend_state {
			Ok(VtxoSpendState::Spendable) => return Ok(false),
			// Decided not to belong in the spendable set.
			Ok(state @ (
				VtxoSpendState::Spent
				| VtxoSpendState::Unclaimed
				| VtxoSpendState::Unregistered
				| VtxoSpendState::HtlcRecvUnclaimed
			)) => {
				debug!("Recovery vtxo {vtxo_id} not spendable ({state:?}), skipping");
				report.push_skipped(vtxo);
			},
			// No usable answer from the server — treat as a failure to be
			// retried, not a clean skip.
			Ok(VtxoSpendState::Unspecified) => {
				warn!("Server returned an unspecified spend state for recovery vtxo {vtxo_id}");
				report.push_failed(vtxo_id, Some(vtxo.amount()));
			},
			Err(e) => {
				warn!("Could not get status for recovery vtxo {vtxo_id}: {:#}", e);
				report.push_failed(vtxo_id, Some(vtxo.amount()));
			},
		}

		Ok(true)
	}

	/// Work out which of `vtxos` this wallet owns, pairing each with its owner
	/// keypair and persisting the keys revealed along the way.
	///
	/// Order-independent: VTXOs whose key was already revealed match directly;
	/// the rest are matched by walking the unrevealed key space once. Each match
	/// reveals every key up to it and extends the [`STOP_GAP`] window, so a later
	/// match can pull in an earlier VTXO a single forward pass would miss.
	///
	/// Idempotent: only keys at or below a match are persisted, so an unmatched
	/// probe leaves no trace and a retry can't ratchet the key index. Owned VTXOs
	/// that fail validation go to `report.failed`; unmatched ones to `report.foreign`.
	async fn resolve_owned_vtxos(
		&self,
		vtxos: Vec<Vtxo<Full>>,
		report: &mut RecoveryReport,
	) -> anyhow::Result<Vec<OwnedVtxo>> {
		// VTXOs we still need to match, indexed by owner pubkey. A pubkey can back
		// more than one VTXO, so keep a list per key.
		let mut pending = HashMap::<PublicKey, Vec<Vtxo<Full>>>::new();
		let mut matched = Vec::<(Vtxo<Full>, Keypair)>::new();

		for vtxo in vtxos {
			match self.pubkey_keypair(&vtxo.user_pubkey()).await? {
				Some((_idx, keypair)) => matched.push((vtxo, keypair)),
				None => pending.entry(vtxo.user_pubkey()).or_default().push(vtxo),
			}
		}

		// Walk the unrevealed key space once, extending the window on every match.
		let start_idx = self.inner.db.get_last_vtxo_key_index().await?.map(|i| i + 1).unwrap_or(0);
		let mut frontier = start_idx.saturating_add(STOP_GAP);
		let mut gap = Vec::<(u32, PublicKey)>::new();
		let mut idx = start_idx;
		while idx <= frontier && !pending.is_empty() {
			let keypair = self.inner.seed.derive_vtxo_keypair(idx);
			let pubkey = keypair.public_key();
			if let Some(owned_vtxos) = pending.remove(&pubkey) {
				// Reveal this key and the unmatched gap keys below it, mirroring the
				// wallet's sequential key issuance.
				for (i, pk) in gap.drain(..) {
					self.inner.db.store_vtxo_key(i, pk).await?;
				}
				self.inner.db.store_vtxo_key(idx, pubkey).await?;
				frontier = idx.saturating_add(STOP_GAP);
				matched.extend(owned_vtxos.into_iter().map(|v| (v, keypair)));
			} else {
				gap.push((idx, pubkey));
			}
			// Stop at the end of the key space rather than overflowing; reaching it
			// would mean scanning the entire u32 range, far beyond any real wallet.
			let Some(next_idx) = idx.checked_add(1) else { break };
			idx = next_idx;
		}

		// Anything still pending never matched within the gap limit, so it's not ours.
		for vtxo in pending.into_values().flatten() {
			report.push_foreign(&vtxo);
		}

		// Validate the matched VTXOs. A validation error (anchor not yet visible,
		// or invalid) is a non-decision, so it's a failure, not a clean skip.
		let mut owned = Vec::with_capacity(matched.len());
		for (vtxo, keypair) in matched {
			if let Err(e) = self.validate_vtxo(&vtxo).await {
				warn!("Could not validate recovery vtxo {}: {:#}", vtxo.id(), e);
				report.push_failed(vtxo.id(), Some(vtxo.amount()));
			} else {
				owned.push(OwnedVtxo::new(vtxo, keypair));
			}
		}

		Ok(owned)
	}

	async fn inner_recover_vtxos(
		&self,
		report: &mut RecoveryReport,
		ids: impl IntoIterator<Item = VtxoId>,
	) -> anyhow::Result<()> {
		let ids = ids.into_iter().collect::<Vec<_>>();
		let owned = self.fetch_valid_owned_vtxos(report, &ids).await?;

		// Ancestor ids of the (newer) VTXOs we've already processed, so we can
		// skip any older recovered VTXO that was spent into a newer one.
		let mut spent = HashSet::<VtxoId>::new();

		for o in owned {
			let id = o.vtxo.id();

			// A descendant we already processed marks this one as spent.
			if spent.contains(&id) {
				debug!("Skipping recovery vtxo {id}: spent into a newer recovered vtxo");
				report.push_skipped(&o.vtxo);
				continue;
			}

			// Add all the ancestor VTXO ids to the spent set
			spent.extend(o.vtxo.ancestor_ids());

			if self.check_vtxo_onchain_status(report, &o.vtxo).await? {
				continue;
			}

			// The server is the authority on whether it was spent elsewhere.
			// Matched exhaustively (no catch-all) so a new spend state forces an
			// explicit decision rather than being silently skipped.
			if self.check_vtxo_server_status(report, &o.vtxo, &o.keypair).await? {
				continue;
			}

			// NB we don't use store_spendable_vtxos to avoid posting the vtxo again
			match self.store_vtxos([&o.vtxo], &VtxoState::Spendable).await {
				Ok(()) => {
					report.push_recovered(&o.vtxo);
					debug!("Recovered spendable vtxo {id} ({})", o.vtxo.amount());
				},
				Err(e) => {
					warn!("Failed to store recovered vtxo {id}: {:#}", e);
					report.push_failed(id, Some(o.vtxo.amount()));
				},
			}
		}

		Ok(())
	}

	pub async fn recover_vtxos(&self, ids: impl IntoIterator<Item = VtxoId>)
		-> anyhow::Result<RecoveryReport>
	{
		let mut report = RecoveryReport::default();
		self.inner_recover_vtxos(&mut report, ids).await?;
		Ok(report)
	}

	/// Rebuild the wallet's spendable VTXO set from the seed-derived recovery
	/// mailbox.
	///
	/// Reads every posted id, fetches the full VTXOs, keeps the ones we own
	/// (deriving their keys), then imports those still spendable. Returns a
	/// [`RecoveryReport`] (see it for why recovered/skipped/failed matters).
	///
	/// VTXOs are consumed newest-first so one spent into a newer recovered VTXO
	/// is seen as already-spent and skipped; the server is consulted for the rest,
	/// since a VTXO can also be spent outside our set (round, offboard, or arkoor
	/// to a third party).
	pub(crate) async fn recover_from_mailbox(&self) -> anyhow::Result<RecoveryReport> {
		let mut report = RecoveryReport::default();

		// Read all owned vtxos, de-duplicated
		let (ids, checkpoint) = self.read_mailbox_recovery_vtxo_ids().await?;
		debug!("Found {} distinct vtxo ids in the recovery mailbox", ids.len());

		self.inner_recover_vtxos(&mut report, ids).await?;

		// Unmatched ids in our own seed-derived mailbox are suspicious: most
		// likely an owned VTXO whose key sits beyond the gap limit (funds may be
		// missing), not a stranger's id. Retrying won't help these — only a wider
		// gap limit can match them — so they get their own warning.
		if !report.foreign.is_empty() {
			warn!(
				"Recovery mailbox held {} vtxo(s) not derivable from this seed within the \
				gap limit ({STOP_GAP}); if any are ours they were not recovered: {:?}",
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
			self.inner_recover_vtxos(&mut report, ids).await?;
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

		// We store the last checkpoint we processed so we can resume from there next time.
		self.inner.db.store_mailbox_checkpoint(checkpoint).await?;

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

