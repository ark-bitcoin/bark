//!
//! The TxNursery makes sure that every tx handed to it makes it onchain.
//!
//! Txs enter the nursery with a confirmation target: the block height
//! by which they are expected to confirm. The nursery persists them and
//! follows up on chain events from the SyncManager:
//!
//! - On every new block it records the confirmations found in the block
//!   and warns the operator about every tx that is past its target
//!   without confirmation.
//! - On every mempool update it rebroadcasts the unconfirmed txs that
//!   are missing from the mempool.
//! - On a reorg it clears the confirmations recorded in evicted blocks,
//!   so the txs are followed up again.
//!
//! The warnings only stop once the tx confirms or the operator
//! explicitly abandons the tx via the admin RPC.
//!
//! The nursery runs entirely in captaind: it is the only process
//! broadcasting txs, so it also runs the follow-up.
//!

use std::collections::HashSet;

use anyhow::Context;
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::encode::serialize;
use bitcoind_async_client::Client as BitcoindClient;
use tracing::warn;

use bitcoin_ext::{BlockHeight, BlockRef, DEEPLY_CONFIRMED};

use crate::bitcoind as bcd;
use crate::database::Db;
use crate::sync::{BlockData, ChainEventListener, RawMempool};

/// What a nursery tx is for; shown in the operator's report and later
/// used to pick per-kind fee bump behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NurseryTxKind {
	/// A round funding tx; the signed vtxo tree commits to its txid.
	Round,
	/// A collaborative offboard tx.
	Offboard,
	/// A vtxo pool issuance funding tx.
	VtxoPool,
	/// An internal wallet tx, e.g. a rounds-to-watchman wallet top-up.
	Internal,
}

impl NurseryTxKind {
	pub fn name(&self) -> &'static str {
		match self {
			Self::Round => "round",
			Self::Offboard => "offboard",
			Self::VtxoPool => "vtxopool",
			Self::Internal => "internal",
		}
	}
}

impl std::str::FromStr for NurseryTxKind {
	type Err = anyhow::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"round" => Ok(Self::Round),
			"offboard" => Ok(Self::Offboard),
			"vtxopool" => Ok(Self::VtxoPool),
			"internal" => Ok(Self::Internal),
			other => Err(anyhow::anyhow!("unknown nursery tx kind: {}", other)),
		}
	}
}

impl std::fmt::Display for NurseryTxKind {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		f.write_str(self.name())
	}
}

#[derive(Clone)]
pub struct TxNursery {
	db: Db,
	bitcoind: BitcoindClient,
}

impl TxNursery {
	/// Create a new nursery. It follows up through chain events, so
	/// register it as a [ChainEventListener] with the SyncManager.
	pub fn new(db: Db, bitcoind: BitcoindClient) -> TxNursery {
		TxNursery { db, bitcoind }
	}

	/// Broadcast a tx that is expected to confirm by the given block
	/// height.
	///
	/// The tx is persisted first, so on success follow-up is guaranteed.
	/// A broadcast error is not returned; the nursery retries on every
	/// mempool update.
	#[tracing::instrument(skip(self, tx))]
	pub async fn broadcast_tx(
		&self,
		tx: Transaction,
		kind: NurseryTxKind,
		confirm_target: BlockHeight,
	) -> anyhow::Result<()> {
		let txid = tx.compute_txid();
		self.db.write(async |t| {
			t.upsert_nursery_tx(&tx, kind, confirm_target).await
		}).await.context("failed to store tx in nursery")?;

		slog!(BroadcastingTx, txid, raw_tx: serialize(&tx));
		if let Err(e) = bcd::broadcast_tx(&self.bitcoind, &tx).await {
			// The nursery will keep retrying on every mempool update.
			slog!(TxBroadcastError, txid, raw_tx: serialize(&tx), error: e.to_string());
		}

		Ok(())
	}

	/// Abandon a nursery tx: stop following it up and stop warning the
	/// operator about it.
	///
	/// Returns false when the txid is not in the nursery, was already
	/// abandoned or has confirmed.
	pub async fn abandon(&self, txid: Txid) -> anyhow::Result<bool> {
		let abandoned = self.db.write(async |t| t.abandon_nursery_tx(txid).await).await?;
		if abandoned {
			slog!(NurseryTxAbandoned, txid);
		}
		Ok(abandoned)
	}

	/// Record the confirmations found in the new block and warn about
	/// every tx that missed its confirmation target.
	async fn process_block(&self, block: &BlockData) -> anyhow::Result<()> {
		let tip_height = block.block_ref.height;
		let deeply_confirmed = tip_height.saturating_sub(DEEPLY_CONFIRMED);
		let txs = self.db.read(async |t| {
			t.get_active_nursery_txs(deeply_confirmed).await
		}).await.context("failed to fetch active nursery txs")?;

		if txs.is_empty() {
			return Ok(());
		}

		let block_txids = block.block.txdata.iter()
			.map(|tx| tx.compute_txid())
			.collect::<HashSet<_>>();

		for tx in &txs {
			if block_txids.contains(&tx.txid) {
				self.register_confirmation(tx.txid, tip_height).await?;
			} else if tx.confirmed_at_height.is_none()
				&& tip_height >= tx.confirm_target_height
			{
				// Keep warning the operator, once per block, until either
				// the tx confirms or the operator abandons it.
				slog!(NurseryTxMissedTarget, txid: tx.txid,
					confirm_target_height: tx.confirm_target_height,
					current_height: tip_height,
				);
			}
		}

		Ok(())
	}

	/// Rebroadcast all unconfirmed nursery txs that are missing from the
	/// mempool.
	async fn process_mempool(&self, mempool: &RawMempool) -> anyhow::Result<()> {
		let txids = self.db.read(async |t| t.get_unconfirmed_nursery_txids().await).await
			.context("failed to fetch unconfirmed nursery txs")?;

		if txids.is_empty() {
			return Ok(());
		}

		let mempool_txids = mempool.txids.iter().collect::<HashSet<_>>();

		for txid in txids {
			if mempool_txids.contains(&txid) {
				continue;
			}

			// Only fetch the raw tx of the (rare) tx that actually needs
			// a rebroadcast, to avoid keeping all of them in memory.
			let tx = self.db.read(async |t| t.get_nursery_raw_tx(txid).await).await
				.with_context(|| format!("failed to fetch raw tx {}", txid))?
				.with_context(|| format!("corrupt db: missing raw tx {}", txid))?;

			slog!(BroadcastingTx, txid, raw_tx: serialize(&tx));
			if let Err(e) = bcd::broadcast_tx(&self.bitcoind, &tx).await {
				slog!(TxBroadcastError, txid, raw_tx: serialize(&tx), error: e.to_string());
			}
		}

		Ok(())
	}

	async fn register_confirmation(
		&self,
		txid: Txid,
		height: BlockHeight,
	) -> anyhow::Result<()> {
		let updated = self.db.write(async |t| {
			t.set_nursery_tx_confirmed(txid, height).await
		}).await?;
		if updated {
			slog!(NurseryTxConfirmed, txid, blockheight: height);
		}
		Ok(())
	}
}

#[async_trait]
impl ChainEventListener for TxNursery {
	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		// NB errors are propagated so the SyncManager re-delivers the
		// block: confirmations are only detected in the block containing
		// the tx, so a swallowed error would miss them forever.
		self.process_block(block).await
	}

	async fn on_reorg(&self, block_ref: BlockRef) -> anyhow::Result<()> {
		// NB errors are propagated here: they make the SyncManager
		// re-deliver the reorg, which is important because a missed
		// eviction would leave txs marked confirmed in orphaned blocks.
		let reorged = self.db.write(async |t| {
			t.clear_nursery_confirmations_after(block_ref.height).await
		}).await.context("failed to clear reorged nursery confirmations")?;

		for (txid, previous_height) in reorged {
			slog!(NurseryTxReorged, txid, previous_height);
		}
		Ok(())
	}

	async fn on_mempool_update(&self, mempool: &RawMempool) -> anyhow::Result<()> {
		// Errors are swallowed on purpose: we retry on the next update.
		if let Err(e) = self.process_mempool(mempool).await {
			warn!("Error processing mempool in nursery: {:#}", e);
		}
		Ok(())
	}
}
