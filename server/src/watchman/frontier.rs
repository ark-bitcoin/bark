use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{Amount, OutPoint, Txid, Witness};
use bitcoin::taproot::LeafVersion;
use tracing::{error, trace};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark::vtxo::policy::clause::{HashDelaySignClause, HashDelaySignClause_v0, TapScriptClause};
use bitcoin_ext::BlockHeight;

use crate::database::{Db, Tx};
use crate::database::htlc_vtxo::{self, HtlcResolution};
use crate::ln::settler::HtlcSettler;
use crate::sync::{BlockData, ChainEventListener, RawMempool};


/// A structure to keep track of partially exited VTXOs across the Ark
///
/// All VTXOs consist of off-chain transactions. This structure tracks when
/// any of these transactions got confirmed onchain.
///
/// The frontier lives in the database. Each block, reorg and reindex loads
/// it into a [Frontier] map and changes both the map and the database. The
/// `_in_tx` methods write through a caller-provided db tx, so that several
/// changes can be committed together.
#[derive(Clone)]
pub struct FrontierChainListener {
	db: Db,
	htlc_settler: Arc<HtlcSettler>,
	/// Keeps chain events from interleaving with a frontier reindex.
	lock: Arc<tokio::sync::Mutex<()>>,
}

/// Set of VTXOs with their confirmation height. Confirmation can be None for
/// funding txs that have not confirmed yet.
pub type Frontier = BTreeMap<VtxoId, (Option<BlockHeight>, ServerVtxo)>;

impl FrontierChainListener {
	pub fn new(db: Db, htlc_settler: Arc<HtlcSettler>) -> Self {
		FrontierChainListener { db, htlc_settler, lock: Arc::new(tokio::sync::Mutex::new(())) }
	}

	/// Hold off chain event processing until the guard is dropped.
	pub async fn lock(&self) -> tokio::sync::MutexGuard<'_, ()> {
		self.lock.lock().await
	}

	/// Register a vtxo in the frontier, writing through the given db tx.
	///
	/// Returns whether the vtxo was newly added.
	pub async fn register_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
		vtxo: ServerVtxo,
		confirmed_height: Option<BlockHeight>,
	) -> anyhow::Result<bool> {
		let vtxo_id = vtxo.id();
		if !frontier.contains_key(&vtxo_id) {
			frontier.insert(vtxo_id, (confirmed_height, vtxo));
			tx.add_vtxo_to_frontier(vtxo_id).await?;
			if let Some(height) = confirmed_height {
				tx.register_vtxo_confirmation(vtxo_id, height).await?;
			}

			slog!(WatchmanAddedVtxo, id: vtxo_id);
			Ok(true)
		} else {
			// The entry can be in the map while the DB row lost its frontier
			// marker; re-run the guarded insert so the row is repaired
			// either way. This is a no-op UPDATE in the normal case.
			tx.add_vtxo_to_frontier(vtxo_id).await?;
			Ok(false)
		}
	}

	/// Remove a vtxo from the frontier because its output was spent on-chain.
	///
	/// Returns whether the vtxo was in the frontier.
	async fn spend(
		&self,
		frontier: &mut Frontier,
		vtxo_id: VtxoId,
		spent_height: BlockHeight,
		spent_txid: Txid,
		witness: &Witness,
	) -> anyhow::Result<bool> {
		self.db.write(async |t| {
			self.spend_in_tx(t, frontier, vtxo_id, spent_height, spent_txid, witness).await
		}).await
	}

	/// Like [Self::spend], but writing through the given db tx.
	pub async fn spend_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
		vtxo_id: VtxoId,
		spent_height: BlockHeight,
		spent_txid: Txid,
		witness: &Witness,
	) -> anyhow::Result<bool> {
		let Some((_height, vtxo)) = frontier.get(&vtxo_id) else {
			return Ok(false);
		};
		// Try to extract a preimage from the spending witness if this is an HTLC vtxo.
		// This must succeed before we proceed — if persisting the preimage fails,
		// block processing will error and the sync manager will retry. On retry the
		// frontier is read from the DB again, restoring this VTXO entry.
		// If the HTLC tx gets unconfirmed and re-confirmed in a reorg, settle()
		// is called again but the DB insert is idempotent (ON CONFLICT DO NOTHING).
		if let Some(preimage) = try_extract_preimage(vtxo, witness) {
			self.htlc_settler.settle(preimage).await
				.context("failed to record HTLC settlement from on-chain spend")?;
		}

		let chain_resolution = classify_htlc_spend(vtxo, witness);
		tx.register_vtxo_spend(vtxo_id, spent_height, spent_txid).await?;
		if let Some(resolution) = chain_resolution {
			htlc_vtxo::set_htlc_vtxo_chain_resolution(tx, vtxo_id, resolution, spent_height).await?;
		}
		frontier.remove(&vtxo_id);

		if let Some(resolution) = chain_resolution {
			slog!(HtlcVtxoResolvedOnChain, vtxo_id, height: spent_height,
				resolution: resolution.as_str().to_owned(),
			);
		}
		Ok(true)
	}

	/// Mark all VTXOs with the given txid in their point as confirmed on this height
	async fn confirm_txid(&self, frontier: &mut Frontier, txid: Txid, height: BlockHeight) -> anyhow::Result<()> {
		// Since we use a BTreeMap, entries are ordered by VtxoId.
		// Since a VtxoId is an outpoint, we can get all points with the
		// same txid by iterating over a range.
		let first = VtxoId::from(OutPoint::new(txid, 0));
		let last = VtxoId::from(OutPoint::new(txid, u32::MAX));
		for (id, (h, vtxo)) in frontier.range_mut(first..last) {
			let was_unconfirmed = h.is_none();
			if !was_unconfirmed {
				error!("Unexpected re-org or duplicate block from SyncManager?");
			}
			self.db.write(async |t| t.register_vtxo_confirmation(*id, height).await).await?;
			*h = Some(height);
			if was_unconfirmed {
				// First on-chain sighting of this frontier VTXO's funding tx:
				// an exit-tree node has landed.
				crate::telemetry::add_unilateral_exit(vtxo.amount().to_sat());
			}
		}
		Ok(())
	}

	/// Set the confirmation height of a single frontier VTXO, repairing a
	/// missed or incorrect confirmation, writing through the given db tx.
	///
	/// Unlike [Self::confirm_txid], this is a no-op when the stored height
	/// already matches, so it is safe to use from a repair pass. Returns
	/// whether anything changed.
	///
	/// Unlike [Self::confirm_txid], this doesn't fire the unilateral exit
	/// telemetry; the caller should do so once the tx is committed.
	pub async fn set_confirmed_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
		vtxo_id: VtxoId,
		height: BlockHeight,
	) -> anyhow::Result<bool> {
		let Some((h, _vtxo)) = frontier.get_mut(&vtxo_id) else {
			return Ok(false);
		};
		if *h == Some(height) {
			return Ok(false);
		}
		tx.register_vtxo_confirmation(vtxo_id, height).await?;
		*h = Some(height);
		Ok(true)
	}

	/// Clear the confirmation height of all VTXOs created by a tx that is
	/// no longer confirmed, writing through the given db tx.
	///
	/// This includes the tx's VTXOs outside the frontier. Returns the
	/// cleared VTXOs with their stale height.
	pub async fn clear_confirmed_txid_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
		txid: Txid,
	) -> anyhow::Result<Vec<(VtxoId, BlockHeight)>> {
		let cleared = tx.clear_vtxo_confirmations_by_txid(txid).await?;
		let first = VtxoId::from(OutPoint::new(txid, 0));
		let last = VtxoId::from(OutPoint::new(txid, u32::MAX));
		for (_id, (h, _vtxo)) in frontier.range_mut(first..=last) {
			*h = None;
		}
		Ok(cleared)
	}

	/// Put the VTXOs spent by a tx that is no longer confirmed back into
	/// the frontier, writing through the given db tx.
	///
	/// The reverse of [Self::spend_in_tx]. A preimage already settled from
	/// the spend stays settled. Returns each restored VTXO with its
	/// confirmation height and its stale spend height.
	pub async fn restore_spent_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
		spending_txid: Txid,
	) -> anyhow::Result<Vec<(VtxoId, Option<BlockHeight>, Amount, BlockHeight)>> {
		let cleared = tx.clear_vtxo_spends_by_txid(spending_txid).await?;
		let mut restored = Vec::with_capacity(cleared.len());
		for (vtxo, confirmed_height, spent_height) in cleared {
			let (id, amount) = (vtxo.id(), vtxo.amount());
			htlc_vtxo::clear_htlc_vtxo_chain_resolution(tx, id).await?;
			self.register_in_tx(tx, frontier, vtxo, confirmed_height).await?;
			restored.push((id, confirmed_height, amount, spent_height));
		}
		Ok(restored)
	}
}

/// Reads the witness to determine if the htlc was spent using the preimage
/// path (fulfilled) or the timeout path (revoked).
///
/// A non-htlc policy or a keypath spend gives `None`: the money moved, but
/// not through a clause that names who got it.
fn classify_htlc_spend(vtxo: &ServerVtxo, witness: &Witness) -> Option<HtlcResolution> {
	let exit_delta = vtxo.exit_delta();
	let server_pubkey = vtxo.server_pubkey();
	let (payment_hash, preimage_script, timeout_script) = match vtxo.policy() {
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) => (
			p.payment_hash,
			p.user_reveals_preimage_clause(exit_delta).tapscript(),
			p.server_claim_after_expiry_clause(server_pubkey, exit_delta).tapscript(),
		),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv_v0(p)) => (
			p.payment_hash,
			p.user_reveals_preimage_clause(exit_delta).tapscript(),
			p.server_claim_after_expiry_clause(server_pubkey, exit_delta).tapscript(),
		),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend(p)) => (
			p.payment_hash,
			p.server_reveals_preimage_clause(server_pubkey, exit_delta).tapscript(),
			p.user_claim_after_expiry_clause(exit_delta).tapscript(),
		),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcSend_v0(p)) => (
			p.payment_hash,
			p.server_reveals_preimage_clause(server_pubkey, exit_delta).tapscript(),
			p.user_claim_after_expiry_clause(exit_delta).tapscript(),
		),
		_ => return None,
	};

	let leaf = witness.taproot_leaf_script()?;
	if leaf.version == LeafVersion::TapScript {
		if leaf.script == preimage_script.as_script() {
			return Some(HtlcResolution::Fulfilled);
		}
		if leaf.script == timeout_script.as_script() {
			return Some(HtlcResolution::Revoked);
		}
	}

	error!(
		"HTLC VTXO {} was spent on-chain through a script we don't recognize, so we \
		cannot tell who got the money for {}. Witness: {:?}",
		vtxo.id(), payment_hash, witness,
	);
	None
}

/// Try to extract a preimage from the witness of a spent HTLC-recv vtxo.
///
/// Only relevant for ServerHtlcRecv: the user reveals the preimage on-chain
/// to claim their incoming Lightning payment. The server needs this preimage
/// to settle the corresponding CLN hold invoice.
///
/// ServerHtlcSend is not checked because the server already learns the
/// preimage from the downstream Lightning node when the payment succeeds.
fn try_extract_preimage(vtxo: &ServerVtxo, witness: &Witness) -> Option<ark::lightning::Preimage> {
	let exit_delta = vtxo.exit_delta();
	let (payment_hash, user_preimage_claim_script, preimage) = match vtxo.policy() {
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) => (
			p.payment_hash,
			p.user_reveals_preimage_clause(exit_delta).tapscript(),
			HashDelaySignClause::extract_preimage_from_witness(witness, p.payment_hash),
		),
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv_v0(p)) => (
			p.payment_hash,
			p.user_reveals_preimage_clause(exit_delta).tapscript(),
			HashDelaySignClause_v0::extract_preimage_from_witness(witness, p.payment_hash),
		),
		_ => return None,
	};

	if preimage.is_none() {
		// The caller persists this spend and drops the frontier entry, so nothing
		// looks at the witness again. Separate the two cases before that happens.
		let spent_user_preimage_claim_script = witness.taproot_leaf_script().is_some_and(|leaf| {
			leaf.version == LeafVersion::TapScript && leaf.script == user_preimage_claim_script.as_script()
		});
		if spent_user_preimage_claim_script {
			// This case means there is disagreement between consensus and our extraction
			// code which would be a serious problem.
			error!(
				"HTLC-recv VTXO {} was claimed on-chain through its preimage clause, \
				but no preimage for {} could be read from the witness. The hold invoice \
				cannot be settled, and the HTLC expires back to the payer. \
				Witness: {:?}",
				vtxo.id(), payment_hash, witness,
			);
		} else {
			trace!(
				"HTLC-recv VTXO {} was spent on-chain, but not through its preimage \
				clause. The hold invoice for {} is not settled from this spend.",
				vtxo.id(), payment_hash,
			);
		}
	}
	preimage
}

#[async_trait::async_trait]
impl ChainEventListener for FrontierChainListener {
	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		let _guard = self.lock().await;
		let height = block.block_ref.height;
		let mut frontier = self.db.read(async |t| t.get_frontier().await).await?;

		for tx in &block.block.txdata {
			let txid = tx.compute_txid();

			// Check if any unconfirmed VTXOs in frontier have this txid as their funding tx
			self.confirm_txid(&mut frontier, txid, height).await?;

			// Find vtxos in the frontier that are spent by this tx
			let mut removed_any = false;
			for input in &tx.input {
				if self.spend(
					&mut frontier, input.previous_output.into(), height, txid, &input.witness,
				).await? {
					removed_any = true;
				}
			}

			// Find new vtxos originating from this tx and add to frontier;
			// register_in_tx() skips vtxos already in the frontier, and a vtxo
			// with a recorded spend was already advanced past (this block
			// is being replayed), so it must not re-enter the frontier.
			if removed_any {
				let new_vtxos = self.db.read(async |t| t.get_vtxos_by_txid(txid).await).await?;
				for (vtxo, spent_height, _) in new_vtxos {
					if spent_height.is_none() {
						self.db.write(async |t| {
							self.register_in_tx(t, &mut frontier, vtxo, Some(height)).await
						}).await?;
					}
				}
			}
		}

		Ok(())
	}

	async fn on_reorg(&self, block_ref: bitcoin_ext::BlockRef) -> anyhow::Result<()> {
		let _guard = self.lock().await;
		// Rollback all transactions that ocurred above this block
		self.db.write(async |t| {
			t.reorg_frontier(block_ref.height).await?;
			htlc_vtxo::clear_htlc_vtxo_chain_resolutions_above(&t, block_ref.height).await?;
			Ok(())
		}).await
	}

	async fn on_mempool_update(&self, _mempool: &RawMempool) -> anyhow::Result<()> {
		// We only care about transactions confirmed in blocks
		Ok(())
	}
}
