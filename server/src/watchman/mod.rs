//!
//! This module defines an alternate server struct that can be used to complement
//! captaind or the main [crate::Server] struct.
//!
//! It runs a subset of the server services, namely those that are not required
//! for user functionality.
//!

mod config;
mod daemon;
mod expiry_payout;
mod frontier;
mod policy;
mod signer;

pub use self::config::Config;
pub use self::daemon::Daemon;
pub use self::frontier::{Frontier, FrontierChainListener};
pub use self::signer::WatchmanSigner;

/// Control messages that can be sent to a running [Watchman].
pub enum Ctrl {
	/// Run both the reaction and the sweep loop right now.
	TriggerSweep,
	/// Re-index the frontier and reply with statistics.
	ReindexFrontier {
		resp: tokio::sync::oneshot::Sender<anyhow::Result<ReindexStats>>,
	},
}

/// Statistics of a frontier reindex. See [Watchman::reindex_frontier].
#[derive(Debug, Default)]
pub struct ReindexStats {
	/// Number of frontier entries verified against the chain.
	pub entries_checked: usize,
	/// Entries whose missed or incorrect confirmation height was repaired.
	pub confirmations_repaired: usize,
	/// VTXOs whose stored confirmation height was cleared because their
	/// tx is no longer confirmed.
	pub confirmations_cleared: usize,
	/// VTXOs whose stored on-chain spend was cleared because the spending
	/// tx is no longer confirmed. They are back in the frontier.
	pub spends_cleared: usize,
	/// Entries whose missed on-chain spend was registered.
	pub spends_repaired: usize,
	/// VTXOs newly added to the frontier as children of repaired spends.
	pub vtxos_added: usize,
	/// Funding txs with unfrontiered VTXOs that were processed.
	pub funding_txs_added: usize,
	/// VTXOs newly registered from unfrontiered funding txs.
	pub funding_vtxos_added: usize,
	/// Entries spent on-chain whose spending tx was not found.
	pub unresolved_spends: usize,
	/// Number of blocks scanned looking for missed spends.
	pub blocks_scanned: usize,
}

/// Handle to a running [Watchman], used to send control messages.
#[derive(Clone)]
pub struct WatchmanHandle {
	ctrl_tx: tokio::sync::mpsc::Sender<Ctrl>,
}

impl WatchmanHandle {
	/// Make the watchman process the entire frontier right now.
	pub fn trigger_sweep(&self) {
		let _ = self.ctrl_tx.try_send(Ctrl::TriggerSweep);
	}

	/// Make the watchman re-index the frontier and wait for the result.
	///
	/// Fails immediately when the watchman is busy with another control
	/// message, and reports an error when it shuts down mid-reindex.
	pub async fn reindex_frontier(&self) -> anyhow::Result<ReindexStats> {
		let (tx, rx) = tokio::sync::oneshot::channel();
		self.ctrl_tx.try_send(Ctrl::ReindexFrontier { resp: tx })
			.map_err(|_| anyhow::anyhow!("watchman busy, try again later"))?;
		rx.await.context("watchman shut down during the reindex")?
	}
}


use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use anyhow::Context;
use bitcoin::{Address, Amount, FeeRate, Transaction, TxIn, TxOut, Sequence, ScriptBuf, Weight, Witness, sighash};
use bitcoin::Txid;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, trace, warn};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoId};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{fee, BlockHeight, BlockRef, TxStatus, P2TR_DUST};
use bitcoin_ext::rpc::BitcoinAsyncRpcExt;
use bitcoin_ext::bdk::KEYCHAIN;
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoind_async_client::Client as BitcoindClient;
use bitcoind_async_client::traits::Reader;

use crate::bitcoind as bcd;
use crate::database::{BlockTable, Db, Tx};
use crate::fee_estimator::FeeEstimator;
use crate::system::RuntimeManager;
use crate::utils::InstrumentedLock;
use crate::wallet::PersistedWallet;
use crate::watchman::policy::ActionContextFetcher;

/// The kind of mempool spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(unused)]
enum SpendKind {
	/// A claim transaction built by the watchman.
	Claim,
	/// A progress transaction built by the watchman.
	Progress,
	/// A foreign spend (e.g. user exit).
	Foreign,
}

/// A transaction spending a vtxo that is currently in the mempool.
#[derive(Debug, Clone)]
struct MempoolSpend {
	txid: Txid,
	fee_rate: FeeRate,
	#[allow(unused)]
	kind: SpendKind,
}

/// The action the watchman should take for a VTXO.
///
/// Every action other than [Action::Sweep] is reactive: some party started an
/// exit on chain and we are racing the timelock that lets them take the money.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
	/// No action needed yet.
	Wait,
	/// Progress the VTXO by broadcasting the next transaction.
	Progress {
		/// The txid of the next transaction to broadcast.
		txid: bitcoin::Txid,
		/// The block height before which the next transaction must be confirmed.
		deadline: BlockHeight,
	},
	/// Claim the VTXO directly to the server's drain address, competing with
	/// the party that can spend it once the deadline passes.
	Claim {
		/// The block height before which the claim must be confirmed.
		deadline: BlockHeight,
	},
	/// Sweep the VTXO to the server's drain address.
	Sweep,
}

/// The actionable work found on the frontier, grouped by the loop that
/// handles it.
struct FrontierWork {
	/// Progress txs to broadcast, soonest deadline first.
	progress: Vec<(Txid, ServerVtxo)>,
	/// VTXOs to claim before a counterparty's timelock matures,
	/// soonest deadline first.
	claims: Vec<ServerVtxo>,
	/// VTXOs to sweep, which have no deadline.
	sweeps: Vec<ServerVtxo>,
}

impl FrontierWork {
	/// All VTXOs for which we intend to broadcast a transaction.
	fn actionable_vtxos(&self) -> impl Iterator<Item = &ServerVtxo> {
		self.claims.iter()
			.chain(self.sweeps.iter())
			.chain(self.progress.iter().map(|(_, v)| v))
	}
}

/// VTXO processing watchman that handles claim and progress txs.
pub struct Watchman {
	/// Configuration parameters controlling watchman behavior.
	config: Config,
	/// Signer used to create claim transactions.
	signer: WatchmanSigner,
	/// Bitcoin RPC client for broadcasting transactions and querying the mempool.
	bitcoind: BitcoindClient,
	/// Database handle for persisting watchman state.
	db: Db,
	/// the block table in the db to use (captaind or watchmand)
	block_table: BlockTable,
	/// fee estimator
	fee_estimator: Arc<FeeEstimator>,
	/// Address where coins from claimed VTXOs are sent.
	drain_spk: ScriptBuf,
	/// Wallet used to pay fees for progress transactions.
	watchman_wallet: InstrumentedLock<PersistedWallet>,
	/// Shared with the SyncManager, which feeds it chain events.
	frontier: FrontierChainListener,
	/// The latest chain tip from the sync manager
	sync_height: watch::Receiver<BlockRef>,
	/// Cache of transactions spending frontier vtxos, keyed by vtxo id.
	///
	/// Includes claims, progress txs, and foreign spends (e.g. user exits).
	mempool_spends: parking_lot::RwLock<HashMap<VtxoId, MempoolSpend>>,
}

impl Watchman {
	pub fn new(
		config: Config,
		signer: WatchmanSigner,
		bitcoind: BitcoindClient,
		db: Db,
		block_table: BlockTable,
		fee_estimator: Arc<FeeEstimator>,
		drain_address: Address,
		wallet: InstrumentedLock<PersistedWallet>,
		frontier: FrontierChainListener,
		sync_height: watch::Receiver<BlockRef>,
	) -> Self {
		Self {
			config,
			signer: signer,
			bitcoind,
			db,
			block_table,
			fee_estimator,
			drain_spk: drain_address.script_pubkey(),
			watchman_wallet: wallet,
			frontier,
			sync_height,
			mempool_spends: parking_lot::RwLock::new(HashMap::new()),
		}
	}

	pub fn sync_height(&self) -> BlockRef {
		*self.sync_height.borrow()
	}

	/// Spawn the watchman process loop and return a handle to control it
	pub fn start(self, rtmgr: RuntimeManager) -> WatchmanHandle {
		let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel(1);
		tokio::spawn(async move {
			Arc::new(self).run(rtmgr, ctrl_rx).await;
		});
		WatchmanHandle { ctrl_tx }
	}

	async fn run(self: Arc<Self>, rtmgr: RuntimeManager, mut ctrl_rx: tokio::sync::mpsc::Receiver<Ctrl>) {
		info!("Starting Watchman...");
		let _worker = rtmgr.spawn_critical("Watchman");

		let mut reaction_timer = tokio::time::interval(self.config.reaction_interval);
		let mut sweep_timer = tokio::time::interval(self.config.sweep_interval);
		let mut completed = self.sync_height.clone();
		let mut expiry_sweeps = JoinSet::new();
		let mut sweep_pending = false;
		loop {
			tokio::select! {
				// Payout mode runs the sweep pass on each block, in a background
				// task. A payout then waits at most one block, and a long pass
				// does not delay the reactions.
				Ok(()) = completed.changed(), if self.db.expiry_payouts() => {
					self.enqueue_expiry_sweep(&mut expiry_sweeps, &mut sweep_pending);
				},
				_ = reaction_timer.tick() => {
					self.process_reactions_logged().await;
					reaction_timer.reset();
				},
				_ = sweep_timer.tick() => {
					self.run_sweeps(&mut expiry_sweeps, &mut sweep_pending).await;
					sweep_timer.reset();
				},
				Some(result) = expiry_sweeps.join_next(), if !expiry_sweeps.is_empty() => {
					if let Err(error) = result { panic!("Expiry sweep task failed: {error}"); }
					if sweep_pending {
						sweep_pending = false;
						self.enqueue_expiry_sweep(&mut expiry_sweeps, &mut sweep_pending);
					}
				},
				Some(ctrl) = ctrl_rx.recv() => match ctrl {
					// a manual trigger runs both loops so we fully catch up
					Ctrl::TriggerSweep => {
						self.process_reactions_logged().await;
						self.run_sweeps(&mut expiry_sweeps, &mut sweep_pending).await;
						reaction_timer.reset();
						sweep_timer.reset();
					},
					Ctrl::ReindexFrontier { resp } => {
						let res = self.reindex_frontier().await;
						if let Err(ref e) = res {
							warn!("Error reindexing the frontier: {:#}", e);
						}
						let _ = resp.send(res);
					},
				},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting Watchman...");
					return;
				},
			}
		}
	}

	async fn process_reactions_logged(&self) {
		if let Err(e) = self.process_reactions().await {
			warn!("Error processing watchman reactions: {:#}", e);
		}
	}

	async fn process_sweeps_logged(&self) {
		if let Err(e) = self.process_sweeps().await {
			warn!("Error processing watchman sweeps: {:#}", e);
		}
	}

	/// Sync funding transactions that are not yet in the frontier.
	///
	/// Queries the database for funding txids with vtxos not in frontier,
	/// checks their confirmation status via bitcoind, and registers them.
	/// Only marks as confirmed if the block is on the synced chain (in the block table).
	///
	/// Every code path that creates funding vtxos adds them to the frontier
	/// in the same database transaction, so this only finds legacy rows or
	/// rows left behind by a bug. It only runs as part of
	/// [Self::reindex_frontier], writing through its db tx.
	///
	/// Returns the number of funding txs processed and the number of vtxos
	/// newly registered in the frontier.
	async fn sync_unfrontiered_funding(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
	) -> anyhow::Result<(usize, usize)> {
		let txids = tx.get_unfrontiered_funding_txids().await?;

		trace!("We got {} unfrontiered funding txs", txids.len());

		if txids.is_empty() {
			return Ok((0, 0));
		}

		let nb_txids = txids.len();
		let mut nb_registered = 0;
		for txid in txids {
			let confirmed_height = match bcd::tx_status(&self.bitcoind, txid).await? {
				// Only use confirmed_height if the block is on the synced chain.
				// Otherwise, add as unconfirmed and it will confirm during the next sync.
				TxStatus::Confirmed(b) if tx.get_block_by_height(
					self.block_table, b.height,
				).await?.is_some_and(|s| s.hash == b.hash) => {
					Some(b.height)
				},
				TxStatus::Mempool | TxStatus::NotFound | TxStatus::Confirmed(_) => None,
			};

			let vtxos = tx.get_vtxos_by_txid(txid).await?;
			let nb_vtxos = vtxos.len();
			for (vtxo, spent_height, _) in vtxos {
				// A vtxo with a recorded spend was already advanced past:
				// only repair its frontier marker so the row stops matching
				// the unfrontiered query.
				if spent_height.is_some() {
					tx.add_vtxo_to_frontier(vtxo.id()).await?;
					continue;
				}
				if self.frontier.register_in_tx(tx, frontier, vtxo, confirmed_height).await? {
					nb_registered += 1;
				}
			}

			slog!(WatchmanAddedFundingTx, txid, nb_vtxos);
		}

		Ok((nb_txids, nb_registered))
	}

	/// Re-index the frontier.
	///
	/// First registers any unfrontiered funding vtxos via
	/// [Self::sync_unfrontiered_funding], then verifies every frontier
	/// entry against bitcoind, repairing missed confirmations and missed
	/// on-chain spends (advancing the frontier to the children of a
	/// spend). Registration runs first so the new entries go through the
	/// same verification, repairing a funding vtxo whose output was
	/// already spent on-chain in the same pass.
	///
	/// A tx that is no longer confirmed has its confirmations cleared and
	/// the spends it made undone, which puts the spent vtxos back in the
	/// frontier to be verified in turn.
	///
	/// All repairs are made in a single db tx, so either the whole
	/// reindex is applied or none of it.
	///
	/// This runs from the watchman control loop, so it never runs
	/// concurrently with claim or sweep processing. The frontier lock is
	/// held for the entire verification pass, so the sync manager cannot
	/// advance the frontier underneath it; it catches up afterwards.
	async fn reindex_frontier(&self) -> anyhow::Result<ReindexStats> {
		let _guard = self.frontier.lock().await;

		let (stats, newly_confirmed) = self.db.write(async |t| {
			let mut frontier = t.get_frontier().await?;
			self.reindex_frontier_in_tx(t, &mut frontier).await
		}).await?;

		// Now that the repairs are committed, fire the telemetry for the
		// first on-chain sightings of frontier VTXOs' funding txs:
		// exit-tree nodes have landed.
		for amount in newly_confirmed {
			crate::telemetry::add_unilateral_exit(amount.to_sat());
		}

		slog!(FrontierReindexComplete,
			entries_checked: stats.entries_checked,
			confirmations_repaired: stats.confirmations_repaired,
			confirmations_cleared: stats.confirmations_cleared,
			spends_cleared: stats.spends_cleared,
			spends_repaired: stats.spends_repaired,
			vtxos_added: stats.vtxos_added,
			funding_txs_added: stats.funding_txs_added,
			funding_vtxos_added: stats.funding_vtxos_added,
			unresolved_spends: stats.unresolved_spends,
			blocks_scanned: stats.blocks_scanned,
		);
		Ok(stats)
	}

	/// The body of [Self::reindex_frontier], running inside its db tx.
	///
	/// Besides the statistics, returns the amounts of the frontier VTXOs
	/// that were unconfirmed before and got a confirmation height now,
	/// for the caller to fire the unilateral exit telemetry once the tx
	/// is committed.
	///
	/// Every db access must go through `tx`: the repairs are not committed
	/// yet, so a separate tx would not see them.
	async fn reindex_frontier_in_tx(
		&self,
		tx: &Tx<'_>,
		frontier: &mut Frontier,
	) -> anyhow::Result<(ReindexStats, Vec<Amount>)> {
		let mut stats = ReindexStats::default();
		let mut newly_confirmed = Vec::new();

		// Phase 1: register unfrontiered funding vtxos, so the phases below
		// verify and repair them like any other entry.
		let (funding_txs_added, funding_vtxos_added) =
			self.sync_unfrontiered_funding(tx, frontier).await?;
		stats.funding_txs_added = funding_txs_added;
		stats.funding_vtxos_added = funding_vtxos_added;

		// Captured under the frontier lock, so it covers the blocks the
		// sync manager processed before the registrations above.
		let sync_height = self.sync_height().height;

		// Snapshot the frontier grouped by virtual_transaction. For each
		// virtual txid, contains set of VTXO id, VTXO confirmation height
		// and VTXO amount.
		let mut by_txid = BTreeMap::<Txid, Vec<(VtxoId, Option<BlockHeight>, Amount)>>::new();
		for (id, (height, vtxo)) in frontier.iter() {
			by_txid.entry(id.to_point().txid).or_default().push((*id, *height, vtxo.amount()));
		}
		let mut groups = by_txid.into_iter().collect::<VecDeque<_>>();

		// Phase 2: verify all frontier entries against bitcoind and
		// collect the entries whose output is already spent on-chain.
		let mut wanted = HashSet::<VtxoId>::new();
		let mut scan_start = None;
		'funding: while let Some((virtual_txid, group)) = groups.pop_front() {
			stats.entries_checked += group.len();

			let block = match bcd::tx_status(&self.bitcoind, virtual_txid).await? {
				TxStatus::Confirmed(b) => b,
				TxStatus::Mempool | TxStatus::NotFound => {
					// A stored height for an unconfirmed tx is stale, most
					// likely from a missed reorg. The sweep loop treats any
					// height as a confirmed exit and would pick actions the
					// chain can't take yet, so clear it. The regular sync
					// sets it again when the tx confirms.
					for (id, height) in self.frontier.clear_confirmed_txid_in_tx(tx, frontier, virtual_txid).await? {
						stats.confirmations_cleared += 1;
						slog!(FrontierClearedConfirmation, vtxo_id: id, height);
					}
					// The VTXOs this tx spends are unspent again. Queue them
					// so their own tx gets verified too, recursively.
					for (id, height, amount, spent_height) in
						self.frontier.restore_spent_in_tx(tx, frontier, virtual_txid).await?
					{
						stats.spends_cleared += 1;
						slog!(FrontierClearedSpend, vtxo_id: id,
							spending_txid: virtual_txid, height: spent_height,
						);
						groups.push_back((id.to_point().txid, vec![(id, height, amount)]));
					}
					continue 'funding;
				},
			};

			// Only record confirmation heights whose block our own sync
			// has processed, so that a later reorg_frontier can roll them
			// back correctly.
			let in_block_table = tx.get_block_by_height(self.block_table, block.height).await?
				.is_some_and(|b| b.hash == block.hash);

			for (id, height, amount) in group {
				if in_block_table && height != Some(block.height) {
					if self.frontier.set_confirmed_in_tx(tx, frontier, id, block.height).await? {
						stats.confirmations_repaired += 1;
						if height.is_none() {
							newly_confirmed.push(amount);
						}
						slog!(FrontierRepairedConfirmation, vtxo_id: id, height: block.height);
					}
				}
				// Query the confirmed utxo set only; mempool spends are
				// left to the regular mempool processing.
				if self.bitcoind.try_get_tx_out(id.to_point(), false).await?.is_none() {
					wanted.insert(id);
					// The stored height can be wrong in either direction,
					// so start from the lower of stored and actual.
					let start = height.map_or(block.height.to_u32(),
						|h| h.to_u32().min(block.height.to_u32()),
					);
					scan_start = Some(scan_start.map_or(start, |s: u32| s.min(start)));
				}
			}
		}

		// Phase 3: find the missed spends with a single forward block scan.
		if let Some(scan_start) = scan_start {
			info!("Starting block scan for watchman reindex: start height {}", scan_start);
			'block: for height in scan_start..=sync_height.to_u32() {
				let height = BlockHeight::from(height);

				let hash = match tx.get_block_by_height(self.block_table, height.into()).await? {
					Some(b) => b.hash,
					// The block table doesn't reach all the way back, but
					// blocks up to sync_height are on the synced chain.
					None => self.bitcoind.get_block_hash(height.to_u32() as u64).await?,
				};
				let block = self.bitcoind.get_block(&hash).await?;
				stats.blocks_scanned += 1;

				for btx in &block.txdata {
					let txid = btx.compute_txid();
					let mut removed_any = false;
					for input in &btx.input {
						let id = VtxoId::from(input.previous_output);
						if wanted.remove(&id) {
							if self.frontier.spend_in_tx(tx, frontier, id, height, txid, &input.witness).await? {
								stats.spends_repaired += 1;
								slog!(FrontierRepairedSpend, vtxo_id: id,
									spending_txid: txid, height,
								);
							}
							removed_any = true;
						}
					}

					// The spending tx may itself create vtxos: register
					// them, and queue any that are already spent again for
					// the remainder of this same forward scan.
					if removed_any {
						let mut spending_txs = vec![(txid, height)];
						while let Some((txid, height)) = spending_txs.pop() {
							let child_vtxos = tx.get_vtxos_by_txid(txid).await?;
							for (vtxo, spent_height, spent_txid) in child_vtxos {
								if let Some(spent_height) = spent_height {
									if let Some(spent_txid) = spent_txid {
										spending_txs.push((spent_txid, spent_height));
									}
								} else {
									// unspent, let's add it as this one got lost
									let child_id = vtxo.id();
									if self.frontier.register_in_tx(tx, frontier, vtxo, Some(height)).await? {
										stats.vtxos_added += 1;
										slog!(FrontierRepairedVtxo, vtxo_id: child_id, height);
									}
									if self.bitcoind.try_get_tx_out(child_id.to_point(), false).await?.is_none() {
										wanted.insert(child_id);
									}
								}
							}
						}
					}
				}

				if wanted.is_empty() {
					break 'block;
				}
			}

			// Anything left was spent in a block above our sync height;
			// the regular sync will pick it up after catching up.
			stats.unresolved_spends = wanted.len();
			for id in wanted {
				slog!(FrontierUnresolvedSpend, vtxo_id: id);
			}
		}

		Ok((stats, newly_confirmed))
	}

	/// Scan the frontier and collect the work to be done, grouped by loop.
	///
	/// This determines the action for every VTXO in the frontier, reports the
	/// frontier telemetry and drops cached mempool spends for VTXOs that no
	/// longer need any action.
	async fn scan_frontier(&self) -> anyhow::Result<FrontierWork> {
		let frontier = self.db.read(async |t| t.get_frontier().await).await?;

		let mut claims = Vec::new();
		let mut progress = Vec::new();
		let mut sweeps = Vec::new();
		let mut wait_volume = Amount::ZERO;

		let ctx = ActionContextFetcher {
			config: &self.config,
			db: &self.db,
			bitcoind: &self.bitcoind,
			chain_tip_height: self.sync_height().height,
		};
		for (confirmed_at, vtxo) in frontier.into_values() {
			match ctx.get_action(&vtxo, confirmed_at).await {
				Action::Wait => {
					wait_volume += vtxo.amount();
				},
				Action::Progress { txid, deadline } => {
					progress.push((deadline, txid, vtxo));
				},
				Action::Claim { deadline } => {
					claims.push((deadline, vtxo));
				},
				Action::Sweep => {
					sweeps.push(vtxo);
				},
			}
		}

		let claim_volume = claims.iter().map(|(_, v)| v.amount()).sum::<Amount>();
		let progress_volume = progress.iter().map(|(_, _, v)| v.amount()).sum::<Amount>();
		let sweep_volume = sweeps.iter().map(|v| v.amount()).sum::<Amount>();
		crate::telemetry::set_frontier_metrics(
			claim_volume.to_sat(),
			progress_volume.to_sat(),
			sweep_volume.to_sat(),
			wait_volume.to_sat(),
		);

		// Sort by deadline, soonest first
		claims.sort_by_key(|(d, _)| *d);
		progress.sort_by_key(|(d, _, _)| *d);

		let work = FrontierWork {
			claims: claims.into_iter().map(|(_, v)| v).collect(),
			progress: progress.into_iter().map(|(_, txid, v)| (txid, v)).collect(),
			sweeps,
		};

		self.clean_mempool_spends(work.actionable_vtxos().map(|v| v.id()));

		Ok(work)
	}

	/// React to on-chain exit activity: progress exit chains and claim VTXOs
	/// before a counterparty's timelock matures.
	///
	/// This is the time-critical half of the watchman's work and runs on the
	/// short [Config::reaction_interval].
	pub async fn process_reactions(&self) -> anyhow::Result<()> {
		let work = self.scan_frontier().await?;

		let vtxos = work.claims.iter().chain(work.progress.iter().map(|(_, v)| v));
		for vtxo in vtxos {
			self.update_mempool_spend(vtxo.id()).await;
		}

		if !work.claims.is_empty() {
			self.process_claims(work.claims).await?;
		}
		if !work.progress.is_empty() {
			self.process_progress_txs(work.progress).await?;
		}

		Ok(())
	}

	/// Sweep VTXOs that only we can spend.
	///
	/// Sweeps have no deadline, so this runs on the much longer
	/// [Config::sweep_interval].
	pub async fn process_sweeps(&self) -> anyhow::Result<()> {
		if self.db.expiry_payouts() {
			return self.process_expiry_sweeps().await;
		}
		let work = self.scan_frontier().await?;

		for vtxo in &work.sweeps {
			self.update_mempool_spend(vtxo.id()).await;
		}

		if !work.sweeps.is_empty() {
			self.process_claims(work.sweeps).await?;
		}

		Ok(())
	}

	/// Process vtxos that need to be claimed by the server, either to beat a
	/// counterparty deadline or to sweep them.
	///
	/// Filters vtxos by broadcast status (skipping those already broadcast with good feerate),
	/// then builds and broadcasts claim txs in chunks.
	async fn process_claims(&self, mut vtxos: Vec<ServerVtxo>) -> anyhow::Result<()> {
		//TODO(stevenroose) adapt feerate to how close the deadline is
		let min_feerate = self.fee_estimator.regular();

		// make sure we always increment with the minimum incremental feerate
		let mut feerate = min_feerate;

		// filter VTXOs to claim
		vtxos.retain(|v| match self.get_mempool_spend(v.id()) {
			None => true,
			Some(spend) => {
				if spend.fee_rate < min_feerate {
					feerate = feerate.max(saturating_add_feerates(
						spend.fee_rate, self.config.incremental_relay_fee,
					));
					true
				} else {
					false
				}
			},
		});

		for chunk in vtxos.chunks(self.config.claim_chunksize.get()) {
			if let Err(e) = self.build_and_broadcast_claim(chunk, feerate).await {
				slog!(ClaimChunkBroadcastFailure, error: e.to_string(),
					vtxos: chunk.iter().map(|v| v.id()).collect(),
				);

				// retry each claim individually to find the culprit
				for vtxo in chunk {
					let slice = std::slice::from_ref(vtxo);
					if let Err(e) = self.build_and_broadcast_claim(slice, feerate).await {
						slog!(ClaimBroadcastFailure, error: e.to_string(), vtxo_id: vtxo.id());
					}
				}
			}
		}

		Ok(())
	}

	/// Update the cached MempoolSpend for a vtxo based on current mempool state.
	///
	/// Detects the spend kind by checking:
	/// - If txid is in virtual_transaction table → Progress
	/// - If all non-anchor outputs go to drain_address → Claim
	/// - Otherwise → Foreign
	async fn update_mempool_spend(&self, vtxo_id: VtxoId) {
		let cached = self.mempool_spends.read().get(&vtxo_id).cloned();

		// Check what's currently spending this vtxo in the mempool
		let spending_txid = match bcd::get_mempool_spending_tx(
			&self.bitcoind, vtxo_id.to_point(),
		).await {
			Ok(Some(txid)) => txid,
			Ok(None) => {
				self.mempool_spends.write().remove(&vtxo_id);
				return;
			},
			Err(e) => {
				warn!("bitcoind err: {:#}", e);
				return;
			},
		};

		// Same as cached - nothing to update
		if cached.as_ref().is_some_and(|c| c.txid == spending_txid) {
			return;
		}

		let feerate = match bcd::chunk_fee_rate(&self.bitcoind, spending_txid).await {
			Ok(Some(feerate)) => feerate,
			// The spend left the mempool between the two calls.
			Ok(None) => {
				self.mempool_spends.write().remove(&vtxo_id);
				return;
			},
			// Any cached entry is a previous spender's, so it is stale; drop it.
			Err(e) => {
				warn!("Failed to fetch feerate of mempool spend {} of vtxo {}: {:#}",
					spending_txid, vtxo_id, e,
				);
				self.mempool_spends.write().remove(&vtxo_id);
				return;
			},
		};

		// Detect spend kind
		let kind = self.detect_spend_kind(spending_txid).await;

		let spend = MempoolSpend { txid: spending_txid, fee_rate: feerate, kind };
		self.mempool_spends.write().insert(vtxo_id, spend);
	}

	/// Detect the kind of spend for a transaction.
	async fn detect_spend_kind(&self, txid: Txid) -> SpendKind {
		// Check if it's a progress tx (in virtual_transaction table)
		if let Ok(Some(_)) = self.db.read(async |t| t.get_virtual_transaction_by_txid(txid).await).await {
			return SpendKind::Progress;
		}

		// Check if it's a claim (all non-anchor outputs go to drain_address)
		if let Ok(tx) = self.bitcoind.get_raw_transaction_verbosity_zero(&txid).await {
			let tx = tx.0;
			let is_claim = tx.output.iter()
				.filter(|o| !o.script_pubkey.is_op_return() && o.script_pubkey != *fee::P2A_SCRIPT)
				.all(|o| o.script_pubkey == self.drain_spk);
			if is_claim {
				return SpendKind::Claim;
			}
		}

		SpendKind::Foreign
	}

	/// Remove mempool spends for vtxos not in the provided list.
	fn clean_mempool_spends(&self, vtxos: impl IntoIterator<Item = VtxoId>) {
		let vtxo_ids = vtxos.into_iter().collect::<HashSet<_>>();
		self.mempool_spends.write().retain(|id, _| vtxo_ids.contains(id));
	}

	/// Get the cached mempool spend for a vtxo, if any.
	fn get_mempool_spend(&self, vtxo: VtxoId) -> Option<MempoolSpend> {
		self.mempool_spends.read().get(&vtxo).cloned()
	}

	/// Build, broadcast, and cache a claim tx for the given vtxos.
	async fn build_and_broadcast_claim(
		&self,
		vtxos: &[ServerVtxo],
		fee_rate: FeeRate,
	) -> anyhow::Result<()> {
		let tx = self.build_claim_tx(vtxos, fee_rate).await?;
		let txid = tx.compute_txid();
		self.broadcast_claim(vtxos, &tx).await?;

		let total_output_value = tx.output.iter().map(|o| o.value).sum::<Amount>();
		let total_input_value = vtxos.iter().map(|v| v.amount()).sum::<Amount>();
		let fee = total_input_value.checked_sub(total_output_value)
			.context("output larger than input amount")?;
		slog!(ClaimBroadcast, txid, fee_rate, total_output_value, fee,
			total_input_value, vtxo_ids: vtxos.iter().map(|v| v.id()).collect(),
		);

		let claim = MempoolSpend {
			txid,
			fee_rate,
			kind: SpendKind::Claim,
		};
		let mut mempool_spends = self.mempool_spends.write();
		for vtxo in vtxos {
			mempool_spends.insert(vtxo.id(), claim.clone());
		}
		Ok(())
	}

	async fn build_claim_tx(
		&self,
		vtxos: &[ServerVtxo],
		fee_rate: FeeRate,
	) -> anyhow::Result<Transaction> {
		let mut inputs = Vec::with_capacity(vtxos.len());
		let mut clauses = Vec::with_capacity(vtxos.len());
		let mut total_input_weight = 0;
		let mut total_input_amount = Amount::ZERO;

		for vtxo in vtxos {
			//TODO(stevenroose) try remove this special case
			if *vtxo.policy() == ServerVtxoPolicy::ServerOwned {
				let input = TxIn {
					previous_output: vtxo.point(),
					script_sig: ScriptBuf::new(),
					sequence: Sequence::ZERO,
					witness: Witness::new(),
				};

				// TxIn base weight (non-witness) + witness weight
				total_input_weight += 4 * input.base_size() + (1 + 1 + 64); // nb items + sig
				total_input_amount += vtxo.amount();

				inputs.push(input);
				clauses.push(None);
			} else {
				let clause = self.signer.find_signable_clause(vtxo).await
					.context(vtxo.id())
					.context("no signable clause for vtxo")?;

				let input = TxIn {
					previous_output: vtxo.point(),
					script_sig: ScriptBuf::new(),
					sequence: clause.sequence().unwrap_or(Sequence::ZERO),
					witness: Witness::new(),
				};

				// TxIn base weight (non-witness) + witness weight
				total_input_weight += 4 * input.base_size() + clause.witness_size(vtxo);
				total_input_amount += vtxo.amount();

				inputs.push(input);
				clauses.push(Some(clause));
			}

			slog!(PreparingVtxoClaim, vtxo_id: vtxo.id(), policy: vtxo.policy().policy_type(),
				value: vtxo.amount(),
			);
		}

		let lock_time = self.sync_height().height.to_locktime()
			.expect("valid block height");

		// Output weight (non-witness data * 4)
		// TxOut: 8 bytes value + varint script_pubkey_len + script_pubkey
		let output_weight = 4 * (8 + 1 + self.drain_spk.len());

		// Transaction overhead weight:
		// - version: 4 bytes * 4 = 16
		// - segwit marker + flag: 2 bytes * 1 = 2
		// - input count varint: 1 byte * 4 = 4 (assuming < 253 inputs)
		// - output count varint: 1 byte * 4 = 4 (assuming < 253 outputs)
		// - locktime: 4 bytes * 4 = 16
		const TX_OVERHEAD_WEIGHT: usize = 2 + 4 * (4 + 1 + 1+ 4);

		let total_weight = Weight::from_wu(
			(TX_OVERHEAD_WEIGHT + total_input_weight + output_weight) as u64,
		);
		let fee = fee_rate.fee_wu(total_weight)
			.context("fee computation overflow")?;
		let output_amount = match total_input_amount.checked_sub(fee) {
			Some(rem) if rem >= P2TR_DUST => rem,
			_ => bail!("insufficient funds: input {} < fee {}", total_input_amount, fee),
		};

		let output = TxOut {
			script_pubkey: self.drain_spk.clone(),
			value: output_amount,
		};

		let mut tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time,
			input: inputs,
			output: vec![output],
		};

		// Sign all inputs
		let prevouts = vtxos.iter().map(|vtxo| vtxo.txout()).collect::<Vec<_>>();
		let prevouts = sighash::Prevouts::All(&prevouts);

		let mut sighash_cache = sighash::SighashCache::new(&mut tx);
		for (input_idx, (vtxo, clause)) in vtxos.iter().zip(&clauses).enumerate() {
			if let Some(clause) = clause {
				let witness = self.signer.sign_input_with_clause(
					vtxo, clause, input_idx, &mut sighash_cache, &prevouts,
				).await.with_context(|| format!(
					"failed to sign script-spend input {} of tx {}",
					input_idx, sighash_cache.transaction().compute_txid(),
				))?;
				*sighash_cache.witness_mut(input_idx).unwrap() = witness;
			} else {
				// keyspend
				let witness = self.signer.sign_input_with_keyspend(
					vtxo, input_idx, &mut sighash_cache, &prevouts,
				).await.with_context(|| format!(
					"failed to sign key-spend input {} of tx {}",
					input_idx, sighash_cache.transaction().compute_txid(),
				))?;
				*sighash_cache.witness_mut(input_idx).unwrap() = witness;
			}
		}

		Ok(tx)
	}

	/// Process vtxos that need to be progressed.
	///
	/// For each vtxo, checks if we already have a progress tx in the mempool:
	/// - If yes and feerate is sufficient: skip (already handled)
	/// - If yes but feerate is too low: needs RBF
	/// - If no existing progress: needs broadcast
	///
	/// The input contains (progress_txid, vtxo) pairs, where progress_txid
	/// is the pre-computed progress transaction that should be broadcast.
	async fn process_progress_txs(&self, mut txs: Vec<(Txid, ServerVtxo)>) -> anyhow::Result<()> {
		//TODO(stevenroose) adapt feerate to how close the deadline is
		let min_fee_rate = self.fee_estimator.regular();

		// make sure we always increment with the minimum incremental feerate
		let mut fee_rate = min_fee_rate;

		// Deduplicate by progress_txid: when multiple vtxos share the same
		// connector tx, only one CPFP must be created for it (P2A can only be
		// spent once per mempool slot).
		let mut seen = HashSet::new();
		txs.retain(|(txid, _)| seen.insert(*txid));

		// filter txs that are already in the mempool with sufficient fee
		txs.retain(|(_, v)| match self.get_mempool_spend(v.id()) {
			None => true,
			Some(spend) => if spend.fee_rate < min_fee_rate {
				fee_rate = fee_rate.max(saturating_add_feerates(
					spend.fee_rate, self.config.incremental_relay_fee,
				));
				true
			} else {
				false
			}
		});

		let mut wallet = self.watchman_wallet.lock().await;

		//TODO(stevenroose) consider a safe strategy for batching here as well
		for (progress_txid, vtxo) in txs {
			if !wallet.has_trusted_balance(self.config.min_cpfp_amount) {
				slog!(NoMoreConfirmedFunds, wallet: wallet.kind().name().into(),
					balance: wallet.balance().trusted,
					address: wallet.next_unused_address(KEYCHAIN).address.into_unchecked(),
				);
				break;
			}

			if let Err(e) = self.process_progress_tx(
				&mut wallet, progress_txid, &vtxo, fee_rate,
			).await {
				slog!(ProgressCpfpFailure, vtxo_id: vtxo.id(), txid: progress_txid,
					error: e.to_string(),
				);
			}
		}

		Ok(())
	}

	/// Process a single progress transaction.
	///
	/// Fetches the signed progress tx from the database and creates a CPFP
	/// transaction to pay its fees, then broadcasts them as a package.
	async fn process_progress_tx(
		&self,
		wallet: &mut PersistedWallet,
		txid: Txid,
		vtxo: &ServerVtxo,
		fee_rate: FeeRate,
	) -> anyhow::Result<()> {
		// Get the progress transaction from the database
		let vtx = self.db.read(async |t| t.get_virtual_transaction_by_txid(txid).await).await?
			.context(txid)
			.context("progress tx not found")?;

		let progress_tx = vtx.signed_tx.context("progress tx missing signature")?.into_owned();

		// Create a CPFP transaction to pay fees for the progress tx
		//TODO(stevenroose) adapt feerate to how close the deadline is
		let fees = MakeCpfpFees::Effective(fee_rate);
		let cpfp_tx = wallet.make_signed_p2a_cpfp(&progress_tx, fees)
			.with_context(|| format!("failed to create CPFP for vtx {}", txid))?;

		// Broadcast the progress tx and CPFP as a package
		let cpfp_txid = cpfp_tx.compute_txid();
		bcd::submit_package(&self.bitcoind, &[progress_tx, cpfp_tx]).await?;

		slog!(ProgressBroadcast, vtxo_id: vtxo.id(), txid, cpfp_txid);

		Ok(())
	}
}

fn saturating_add_feerates(f1: FeeRate, f2: FeeRate) -> FeeRate {
	FeeRate::from_sat_per_kwu(
		f1.to_sat_per_kwu().saturating_add(f2.to_sat_per_kwu())
	)
}
