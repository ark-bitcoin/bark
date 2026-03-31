use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{OutPoint, Txid, Witness};
use tokio::sync::RwLock;
use tracing::{error, warn};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoId, VtxoPolicy};
use ark::vtxo::policy::clause::HashDelaySignClause;
use bitcoin_ext::BlockHeight;

use crate::database::Db;
use crate::ln::settler::HtlcSettler;
use crate::sync::{BlockData, ChainEventListener, RawMempool};


/// A structure to keep track of partially exited VTXOs across the Ark
///
/// All VTXOs consist of off-chain transactions. This structure tracks when
/// any of these transactions got confirmed onchain.
pub struct VtxoExitFrontier {
	db: Db,
	htlc_settler: Arc<HtlcSettler>,
	frontier: BTreeMap<VtxoId, (Option<BlockHeight>, ServerVtxo)>,
}

impl VtxoExitFrontier {
	pub async fn init(db: Db, htlc_settler: Arc<HtlcSettler>) -> anyhow::Result<Self> {
		let frontier = db.get_frontier().await?;
		Ok(VtxoExitFrontier { db, htlc_settler, frontier })
	}

	pub async fn register(
		&mut self,
		vtxo: ServerVtxo,
		confirmed_height: Option<BlockHeight>,
	) -> anyhow::Result<()> {
		let vtxo_id = vtxo.id();
		self.frontier.insert(vtxo.id(), (confirmed_height, vtxo));
		self.db.add_vtxo_to_frontier(vtxo_id).await?;

		if let Some(height) = confirmed_height {
			self.db.register_vtxo_confirmation(vtxo_id, height).await?;
		}

		slog!(WatchmanAddedVtxo, id: vtxo_id);

		Ok(())
	}

	pub async fn spend(
		&mut self,
		vtxo_id: VtxoId,
		spent_height: BlockHeight,
		spent_txid: Txid,
		witness: &Witness,
	) -> anyhow::Result<bool> {
		if let Some((_height, vtxo)) = self.frontier.remove(&vtxo_id) {
			// Try to extract a preimage from the spending witness if this is an HTLC vtxo.
			// This must succeed before we proceed — if persisting the preimage fails,
			// block processing will error and the sync manager will retry. On retry the
			// in-memory frontier is rebuilt from the DB, restoring this VTXO entry.
			// If the HTLC tx gets unconfirmed and re-confirmed in a reorg, settle()
			// is called again but the DB insert is idempotent (ON CONFLICT DO NOTHING).
			if let Some(preimage) = try_extract_preimage(&vtxo, witness) {
				self.htlc_settler.settle(preimage).await
					.context("failed to record HTLC settlement from on-chain spend")?;
			}

			self.db.register_vtxo_spend(vtxo_id, spent_height, spent_txid).await?;
			Ok(true)
		} else {
			Ok(false)
		}
	}

	/// Mark all VTXOs with the given txid in their point as confirmed on this height
	pub async fn confirm_txid(&mut self, txid: Txid, height: BlockHeight) -> anyhow::Result<()> {
		// Since we use a BTreeMap, entries are ordered by VtxoId.
		// Since a VtxoId is an outpoint, we can get all points with the
		// same txid by iterating over a range.
		let first = VtxoId::from(OutPoint::new(txid, 0));
		let last = VtxoId::from(OutPoint::new(txid, u32::MAX));
		for (id, h) in self.frontier.range_mut(first..last).map(|(id, (h, _v))| (id, h)) {
			if h.is_some() {
				error!("Unexpected re-org or duplicate block from SyncManager?");
			}
			*h = Some(height);
			self.db.register_vtxo_confirmation(*id, height).await?;
		}
		Ok(())
	}

	pub async fn reload(&mut self) -> anyhow::Result<()> {
		self.frontier = self.db.get_frontier().await?;
		Ok(())
	}

	/// Returns an iterator over the current frontier with confirmation heights.
	///
	/// Each item is a reference to a VTXO paired with its confirmation height
	/// (None if unconfirmed).
	pub fn get(&self) -> impl Iterator<Item = (&ServerVtxo, Option<BlockHeight>)> {
		self.frontier.values().map(|(h, v)| (v, *h))
	}

	#[cfg(test)]
	pub async fn check_frontier_matches_db(&self) -> anyhow::Result<()> {
		let db_frontier = self.db.get_frontier().await?;

		let mut local = self.frontier.keys().collect::<Vec<_>>();
		let mut db = db_frontier.keys().collect::<Vec<_>>();
		local.sort();
		db.sort();

		if local != db {
			bail!("frontier doesn't match db");
		}
		Ok(())
	}
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
	let payment_hash = match vtxo.policy() {
		ServerVtxoPolicy::User(VtxoPolicy::ServerHtlcRecv(p)) => p.payment_hash,
		_ => return None,
	};
	let preimage = HashDelaySignClause::extract_preimage_from_witness(witness, payment_hash);
	if preimage.is_none() {
		// Not necessarily an error: the VTXO may have been spent via the
		// arkoor path by its next owner after the HTLC was settled between
		// user and server.
		warn!(
			"HTLC-recv VTXO {} spent on-chain without preimage in witness \
			(witness len={}). Hold invoice for {} will not be settled from \
			this spend.",
			vtxo.id(), witness.len(), payment_hash,
		);
	}
	preimage
}

#[async_trait::async_trait]
impl ChainEventListener for Arc<RwLock<VtxoExitFrontier>> {
	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		let height = block.block_ref.height;
		let mut frontier = self.write().await;

		for tx in &block.block.txdata {
			let txid = tx.compute_txid();

			// Check if any unconfirmed VTXOs in frontier have this txid as their funding tx
			frontier.confirm_txid(txid, height).await?;

			// Find vtxos in the frontier that are spent by this tx
			let mut removed_any = false;
			for input in &tx.input {
				if frontier.spend(
					input.previous_output.into(), height, txid, &input.witness,
				).await? {
					removed_any = true;
				}
			}

			// Find new vtxos originating from this tx and add to frontier
			if removed_any {
				let new_vtxos = frontier.db.get_vtxos_by_txid(txid).await?;
				for vtxo in new_vtxos {
					// Only add if not already in frontier
					if !frontier.frontier.contains_key(&vtxo.id()) {
						frontier.register(vtxo, Some(height)).await?;
					}
				}
			}
		}

		#[cfg(test)]
		frontier.check_frontier_matches_db().await?;

		Ok(())
	}

	async fn on_reorg(&self, block_ref: bitcoin_ext::BlockRef) -> anyhow::Result<()> {
		let mut frontier = self.write().await;

		// Rollback DB state above fork point.
		//
		// htlc_settlement entries are intentionally NOT rolled back: once a
		// preimage appears on-chain (even in a block that is later reorged),
		// it is public knowledge. Settling the CLN hold invoice is still
		// correct — the receiver already knows the preimage and could
		// re-broadcast the claiming tx at any time.
		frontier.db.reorg_frontier(block_ref.height).await?;

		// Reload in-memory frontier
		frontier.reload().await?;

		Ok(())
	}

	async fn on_mempool_update(&self, _mempool: &RawMempool) -> anyhow::Result<()> {
		// We only care about transactions confirmed in blocks
		Ok(())
	}
}
