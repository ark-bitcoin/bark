use std::collections::HashSet;
use std::time::{Instant, UNIX_EPOCH, SystemTime};

use anyhow::Context;

use bitcoin_ext::bdk::{KEYCHAIN, WalletExt};
use bitcoin_ext::BlockRef;

use crate::sync::{ChainEventListener, BlockData, RawMempool};
use crate::telemetry;
use crate::utils::InstrumentedLock;
use crate::wallet::PersistedWallet;

/// Implementation of [ChainEventListener] for wallets wrapped in [InstrumentedLock].
///
/// This allows wallets to receive block events from the [SyncManager] and stay
/// in sync with the blockchain without needing to poll bitcoind independently.
///
/// The implementation:
/// - On new blocks: applies the block to the BDK wallet and persists changes
/// - On reorgs: logs the event; BDK handles reorgs internally when subsequent
///   blocks are applied that connect to a different chain
///
/// Note: Initial wallet sync (catchup from checkpoint to current tip) still uses
/// BDK's Emitter. This listener is only used for ongoing sync after the wallet
/// is caught up.
#[async_trait]
impl ChainEventListener for InstrumentedLock<PersistedWallet> {
	#[tracing::instrument(skip_all, fields(wallet = self.name(), height = block.block_ref.height))]
	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		let mut wallet = self.lock().await;
		let started = Instant::now();

		let height = block.block_ref.height;
		let wallet_name = wallet.kind.name();

		let prev_height = wallet.latest_checkpoint().height();
		let prev_balance = wallet.balance();

		slog!(WalletSyncStarting, wallet: wallet_name.into(), block_height: prev_height);

		// BDK requires the BlockId of the parent block to verify the chain connection
		let connected_to = bdk_wallet::chain::BlockId {
			height: height.saturating_sub(1),
			hash: block.block.header.prev_blockhash,
		};

		wallet.wallet.apply_block_connected_to(&block.block, height, connected_to)
			.with_context(|| format!(
				"failed applying block {} to {} wallet", height, wallet_name,
			))?;

		wallet.persist().await
			.with_context(|| format!(
				"failed persisting {} wallet after block {}", wallet_name, height,
			))?;

		let new_height = wallet.latest_checkpoint().height();
		slog!(WalletSyncComplete, wallet: wallet_name.into(), sync_time: started.elapsed(),
			new_block_height: new_height, previous_block_height: prev_height,
			next_address: wallet.next_unused_address(KEYCHAIN).address.into_unchecked(),
		);

		let balance = wallet.balance();
		if balance != prev_balance {
			slog!(WalletBalanceUpdated, wallet: wallet_name.into(), balance: balance.clone(),
				block_height: new_height,
			);
		} else {
			slog!(WalletBalanceUnchanged, wallet: wallet_name.into(), balance: balance.clone(),
				block_height: new_height,
			);
		}

		telemetry::set_wallet_balance(wallet.kind, balance);

		Ok(())
	}

	#[tracing::instrument(skip_all, fields(wallet = self.name(), height = _reorg_to.height))]
	async fn on_reorg(&self, _reorg_to: BlockRef) -> anyhow::Result<()> {
		// No action needed on reorg notification.
		//
		// BDK handles reorgs for us
		Ok(())
	}


	/// The implementation only handles evictions: it detects transactions that were
	/// previously unconfirmed in the wallet but are no longer in the mempool.
	///
	/// We will not process evictions of fully owned transactions. These are
	/// txs for which every input originates from the wallet. This prevents
	/// false evictions.
	///
	/// When someone attempts to send money to it will only be added
	/// to the wallet when it is confirmed in at least one block. Transactions
	/// created by this server will be added manually.
	#[tracing::instrument(skip_all, fields(wallet = self.name()))]
	async fn on_mempool_update(&self, mempool: &RawMempool) -> anyhow::Result<()> {
		let mut wallet = self.lock().await;

		// Find unconfirmed transactions in our wallet that are no longer in the mempool
		// We will not evict fully owned transactions
		let mempool_set = mempool.txids.iter().collect::<HashSet<_>>();
		let evicted: Vec<_> = wallet.wallet.unconfirmed_txids()
			.filter(|txid| !wallet.is_fully_owned_tx(*txid))
			.filter(|txid| !mempool_set.contains(txid))
			.collect();

		if evicted.is_empty() {
			return Ok(());
		}

		for txid in &evicted {
			slog!(TxEvicted, wallet: wallet.kind.name().into(), txid: *txid);
		}

		let now = SystemTime::now().duration_since(UNIX_EPOCH)
			.expect("Unix epoch is in the past").as_secs();
		wallet.wallet.apply_evicted_txs(evicted.into_iter().map(|txid| (txid, now)));

		wallet.persist().await
			.with_context(|| format!(
				"failed persisting {} wallet after mempool update", wallet.kind.name(),
			))?;

		Ok(())
	}
}
