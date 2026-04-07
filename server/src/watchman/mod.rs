//!
//! This module defines an alternate server struct that can be used to complement
//! captaind or the main [crate::Server] struct.
//!
//! It runs a subset of the server services, namely those that are not required
//! for user functionality.
//!

mod config;
mod daemon;
mod frontier;
mod policy;
mod signer;

pub use self::config::Config;
pub use self::daemon::Daemon;
pub use self::frontier::VtxoExitFrontier;
pub use self::signer::WatchmanSigner;


use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Context;
use bitcoin::absolute::LockTime;
use bitcoin::{Address, Amount, FeeRate, Transaction, TxIn, TxOut, Sequence, ScriptBuf, Weight, Witness, sighash};
use bitcoin::Txid;
use tokio::sync::watch;
use tracing::{info, trace, warn};

use ark::{ServerVtxo, ServerVtxoPolicy, VtxoId};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{fee, BlockHeight, BlockRef, TxStatus, P2TR_DUST};
use bitcoin_ext::bdk::{WalletExt, KEYCHAIN};
use bitcoin_ext::cpfp::MakeCpfpFees;
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};

use crate::database::{BlockTable, Db};
use crate::fee_estimator::FeeEstimator;
use crate::system::RuntimeManager;
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
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
	/// No action needed yet.
	Wait,
	/// Progress the VTXO by broadcasting the next transaction.
	Progress {
		/// The txid of the next transaction to broadcast.
		txid: bitcoin::Txid,
		/// The block height before which the next transaction must be confirmed.
		deadline: Option<BlockHeight>,
	},
	/// Claim the VTXO directly to the server's drain address.
	Claim {
		/// The block height before which the claim must be confirmed.
		deadline: Option<BlockHeight>,
	},
}

/// VTXO processing watchman that handles claim and progress txs.
pub struct Watchman {
	/// Configuration parameters controlling watchman behavior.
	config: Config,
	/// Signer used to create claim transactions.
	signer: WatchmanSigner,
	/// Bitcoin RPC client for broadcasting transactions and querying the mempool.
	bitcoind: BitcoinRpcClient,
	/// Database handle for persisting watchman state.
	db: Db,
	/// the block table in the db to use (captaind or watchmand)
	block_table: BlockTable,
	/// fee estimator
	fee_estimator: Arc<FeeEstimator>,
	/// Address where coins from claimed VTXOs are sent.
	drain_spk: ScriptBuf,
	/// Wallet used to pay fees for progress transactions.
	watchman_wallet: Arc<tokio::sync::Mutex<PersistedWallet>>,
	/// The set of VTXOs the watchman is responsible for monitoring and claiming.
	/// Shared with SyncManager for chain event handling.
	frontier: Arc<tokio::sync::RwLock<VtxoExitFrontier>>,
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
		bitcoind: BitcoinRpcClient,
		db: Db,
		block_table: BlockTable,
		fee_estimator: Arc<FeeEstimator>,
		drain_address: Address,
		wallet: Arc<tokio::sync::Mutex<PersistedWallet>>,
		frontier: Arc<tokio::sync::RwLock<VtxoExitFrontier>>,
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

	/// Run the watchman process loop.
	///
	/// Periodically processes all VTXOs in the frontier, handling claims
	/// and progress txs as needed.
	pub async fn run(&self, rtmgr: RuntimeManager) {
		info!("Starting Watchman...");
		let _worker = rtmgr.spawn_critical("Watchman");

		let mut timer = tokio::time::interval(self.config.process_interval);
		loop {
			tokio::select! {
				_ = timer.tick() => {},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting Watchman...");
					return;
				},
			}

			// Sync the watchman wallet to update balance and detect confirmed UTXOs.
			if let Err(e) = self.watchman_wallet.lock().await.sync(&self.bitcoind, false).await {
				warn!("Error syncing watchman wallet: {:#}", e);
			}

			//TODO(stevenroose) this call seems expensive and really not urgent
			// we only realistically need to do this once every hour, or maybe half exit delta or so
			if let Err(e) = self.sync_unfrontiered_funding().await {
				warn!("Error syncing unfrontiered funding: {:#}", e);
			}

			if let Err(e) = self.process_all().await {
				warn!("Error processing watchman: {:#}", e);
			}

			timer.reset();
		}
	}

	/// Sync funding transactions that are not yet in the frontier.
	///
	/// Queries the database for funding txids with vtxos not in frontier,
	/// checks their confirmation status via bitcoind, and registers them.
	/// Only marks as confirmed if the block is on the synced chain (in the block table).
	pub async fn sync_unfrontiered_funding(&self) -> anyhow::Result<()> {
		let txids = self.db.get_unfrontiered_funding_txids().await?;

		if txids.is_empty() {
			return Ok(());
		}

		trace!("We got {} unfrontiered funding txs", txids.len());

		let mut frontier = self.frontier.write().await;

		for txid in txids {
			let confirmed_height = match self.bitcoind.tx_status(txid)? {
				// Only use confirmed_height if the block is on the synced chain.
				// Otherwise, add as unconfirmed and it will confirm during the next sync.
				TxStatus::Confirmed(b) if self.db.get_block_by_height(
					self.block_table, b.height,
				).await?.is_some() => {
					Some(b.height)
				},
				TxStatus::Mempool | TxStatus::NotFound | TxStatus::Confirmed(_) => None,
			};

			let vtxos = self.db.get_vtxos_by_txid(txid).await?;
			let nb_vtxos = vtxos.len();
			for vtxo in vtxos {
				frontier.register(vtxo, confirmed_height).await?;
			}

			slog!(WatchmanAddedFundingTx, txid, nb_vtxos);
		}

		Ok(())
	}

	/// Process all VTXOs in the frontier.
	///
	/// Iterates over all VTXOs, determines the appropriate action for each,
	/// and dispatches to the corresponding handler:
	/// - Wait: no action needed
	/// - Progress: passed to progress
	/// - Claim: passed to process_claims
	pub async fn process_all(&self) -> anyhow::Result<()> {
		let frontier = self.frontier.read().await;

		let mut claims = Vec::new();
		let mut progress = Vec::new();

		let ctx = ActionContextFetcher {
			config: &self.config,
			db: &self.db,
			bitcoind: &self.bitcoind,
			chain_tip_height: self.sync_height().height,
		};
		for (vtxo, confirmed_at) in frontier.get() {
			match ctx.get_action(vtxo, confirmed_at).await {
				Action::Wait => {},
				Action::Progress { txid, deadline } => {
					progress.push((deadline, txid, vtxo.clone()));
				},
				Action::Claim { deadline } => {
					claims.push((deadline, vtxo.clone()));
				},
			}
		}
		drop(frontier); // Release read lock before processing

		// Sort by deadline (soonest first, None last)
		claims.sort_by_key(|(d, _)| d.map(|h| (0u8, h)).unwrap_or((1u8, 0)));
		progress.sort_by_key(|(d, _, _)| d.map(|h| (0u8, h)).unwrap_or((1u8, 0)));

		let claims = claims.into_iter().map(|(_, v)| v).collect::<Vec<_>>();
		let progress = progress.into_iter().map(|(_, txid, v)| (txid, v)).collect::<Vec<_>>();

		// Clean and update on combined list
		let progress_vtxos = progress.iter().map(|(_, v)| v);
		let all_vtxos = claims.iter().chain(progress_vtxos);
		self.clean_mempool_spends(all_vtxos.clone().map(|v| v.id()));
		for vtxo in all_vtxos {
			self.update_mempool_spend(vtxo.id()).await;
		}

		if !claims.is_empty() {
			self.process_claims(claims).await?;
		}
		if !progress.is_empty() {
			self.process_progress_txs(progress).await?;
		}

		Ok(())
	}

	/// Process vtxos that need to be claimed by the server.
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
		let spending_txid = match self.bitcoind.get_mempool_spending_tx(vtxo_id.utxo()) {
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

		let Ok(Some(feerate)) = self.bitcoind.estimate_mempool_feerate(spending_txid) else {
			self.mempool_spends.write().remove(&vtxo_id);
			return;
		};

		// Detect spend kind
		let kind = self.detect_spend_kind(spending_txid).await;

		let spend = MempoolSpend { txid: spending_txid, fee_rate: feerate, kind };
		self.mempool_spends.write().insert(vtxo_id, spend);
	}

	/// Detect the kind of spend for a transaction.
	async fn detect_spend_kind(&self, txid: Txid) -> SpendKind {
		// Check if it's a progress tx (in virtual_transaction table)
		if let Ok(Some(_)) = self.db.get_virtual_transaction_by_txid(txid).await {
			return SpendKind::Progress;
		}

		// Check if it's a claim (all non-anchor outputs go to drain_address)
		if let Ok(tx) = self.bitcoind.get_raw_transaction(&txid, None) {
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
		self.bitcoind.broadcast_tx(&tx)?;

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

		let lock_time = LockTime::from_height(self.sync_height().height)
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
		let vtx = self.db.get_virtual_transaction_by_txid(txid).await?
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
		self.bitcoind.submit_package(&[progress_tx, cpfp_tx])?;

		slog!(ProgressBroadcast, vtxo_id: vtxo.id(), txid, cpfp_txid);

		Ok(())
	}
}

fn saturating_add_feerates(f1: FeeRate, f2: FeeRate) -> FeeRate {
	FeeRate::from_sat_per_kwu(
		f1.to_sat_per_kwu().saturating_add(f2.to_sat_per_kwu())
	)
}
