//!
//! This module implements the logic to sweep up all expired round UTXOs.
//! Generally this means
//! - sweeping the outputs of the root tx if none of the offchain txs were broadcast
//! - sweeping all the unspent outputs of intermediate vtxo tree txs if some were spent
//! - sweeping all unused connector outputs
//!
//! Some things to keep in mind:
//!
//! # Sweep VTXOs before connectors
//!
//! We need the connectors in case a user attempts a malicious exit.
//! Also, the connectors have way less money in them, so we don't need them as urgently.
//! As such, our strategy is to keep connectors untouched until we are sure all VTXO tree
//! outputs are confirmed.
//!
//! # Races with competing txs
//!
//! All of the VTXO outputs we're going to be spending have alternative spend paths. Either
//! fee anchors (anyone can spend) or VTXO outputs (covenant spend stays valid while we can sweep).
//! This means that it is possible that there may exist transactions competing with ours.
//! None of these txs can steal our money, so "winning the race" is not critical;
//! but they often do incur an extra cost to us, so we prefer to get as little as them confirmed
//! as possible.
//!
//! As such, there are two possible strategies we can use to deal with competing transactions:
//! 1. *double spend": ignore them and simply double spend them,
//! then waiting to see which one confirms and adjust accordingly.
//! 2. *descend*: create descendent txs from the existing ones and make both confirm.
//!
//! In theory both strategies can be the optimal strategy in specific situations, but in practice,
//! the *descend* strategy is going to be way more complicated when it comes to avoiding
//! stuck transactions.
//!
//! Therefore, the strategy implemented in this module is the simpler *double spend* strategy.
//!

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::Context;
use ark::tree::signed::cosign_taproot;
use ark::vtxo::VtxoSpec;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{XOnlyPublicKey, Keypair};
use bitcoin::{
	psbt, sighash, Address, Amount, FeeRate, Network, OutPoint, Psbt, Sequence, Transaction, TxOut, Txid, Weight
};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin_ext::{BlockHeight, TaprootSpendInfoExt, TransactionExt, DEEPLY_CONFIRMED};
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt, RpcApi};
use tokio::sync::mpsc;
use tracing::{error, info, trace, warn};
use ark::musig;
use ark::connectors::ConnectorChain;
use ark::rounds::{RoundId, ROUND_TX_VTXO_TREE_VOUT};

use crate::database::rounds::StoredRound;
use crate::fee_estimator::FeeEstimator;
use crate::psbtext::{PsbtExt, PsbtInputExt, SweepMeta};
use crate::system::RuntimeManager;
use crate::txindex::{self, TxIndex};
use crate::txindex::broadcast::TxNursery;
use crate::{database, telemetry};

use std::sync::Arc;


#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	#[serde(with = "crate::utils::serde::duration")]
	pub round_sweep_interval: Duration,
	/// Don't make sweep txs for amounts lower than this amount.
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub sweep_threshold: Amount,
}

impl Default for Config {
	fn default() -> Self {
	    Self {
			round_sweep_interval: Duration::from_secs(60 * 60),
			sweep_threshold: Amount::from_sat(1_000_000),
		}
	}
}

struct BoardSweepInput {
	point: OutPoint,
	vtxo_spec: VtxoSpec,
}

impl BoardSweepInput {
	fn amount(&self) -> Amount {
		self.vtxo_spec.amount
	}

	fn weight(&self) -> Weight {
		ark::vtxo::EXIT_TX_WEIGHT
	}

	/// Calculate the surplus that can be gained from sweeping this input.
	///
	/// This is calculated as the inputs value subtracted with the cost
	/// of spending it with the given fee rate.
	///
	/// If negative, returns [None].
	fn surplus(&self, feerate: FeeRate) -> Option<Amount> {
		self.amount().checked_sub(feerate * self.weight())
	}

	fn psbt(&self) -> psbt::Input {
		let spec = &self.vtxo_spec;
		let combined_pubkey = musig::combine_keys([
			self.vtxo_spec.policy.user_pubkey(), spec.server_pubkey,
		]);
		let taproot = cosign_taproot(combined_pubkey, spec.server_pubkey, spec.expiry_height);
		let utxo = TxOut {
			value: spec.amount,
			script_pubkey: taproot.script_pubkey(),
		};

		let mut ret = psbt::Input{
			witness_utxo: Some(utxo),
			sighash_type: Some(sighash::TapSighashType::Default.into()),
			tap_internal_key: Some(combined_pubkey),
			tap_scripts: taproot.psbt_tap_scripts(),
			tap_merkle_root: Some(taproot.merkle_root().unwrap()),
			non_witness_utxo: None,
			..Default::default()
		};
		ret.set_sweep_meta(SweepMeta::Board);
		ret
	}
}

struct RoundSweepInput<'a> {
	point: OutPoint,
	utxo: TxOut,
	internal_key: XOnlyPublicKey,
	round: &'a ExpiredRound,
	sweep_meta: SweepMeta,
	weight: Weight,
}

impl<'a> RoundSweepInput<'a> {
	fn amount(&self) -> Amount {
		self.utxo.value
	}

	/// Calculate the surplus that can be gained from sweeping this input.
	///
	/// This is calculated as the inputs value subtracted with the cost
	/// of spending it with the given fee rate.
	///
	/// If negative, returns [None].
	fn surplus(&self, feerate: FeeRate) -> Option<Amount> {
		self.amount().checked_sub(feerate * self.weight)
	}

	fn psbt(&self) -> psbt::Input {
		let round_cosign_pk = self.round.round.signed_tree.spec.funding_tx_cosign_pubkey();
		let taproot = self.round.round.signed_tree.spec.internal_taproot(round_cosign_pk);
		let mut ret = psbt::Input{
			witness_utxo: Some(self.utxo.clone()),
			sighash_type: Some(sighash::TapSighashType::Default.into()),
			tap_internal_key: Some(self.internal_key),
			tap_scripts: taproot.psbt_tap_scripts(),
			tap_merkle_root: Some(taproot.merkle_root().unwrap()),
			non_witness_utxo: None,
			..Default::default()
		};
		ret.set_sweep_meta(self.sweep_meta.clone());
		ret
	}
}

struct ExpiredRound {
	id: RoundId,
	round: StoredRound,
	connectors: ConnectorChain,

	/// All transactions in this rounds vtxo tree, from the leaves to the root.
	vtxo_txs: Vec<Transaction>,
}

impl ExpiredRound {
	fn new(_id: RoundId, _round: StoredRound) -> Self {
		unimplemented!();
	}
}

/// finish a sweeper-made tx
///
/// We need a dedicated fn here because we don't have a PersistedWallet.
fn finish_tx(wallet: &bdk_wallet::Wallet, mut psbt: Psbt) -> anyhow::Result<Transaction> {
	#[allow(deprecated)]
	let opts = bdk_wallet::SignOptions {
		trust_witness_utxo: true,
		..Default::default()
	};
	let finalized = wallet.sign(&mut psbt, opts).context("error signing psbt")?;
	ensure!(finalized, "tx not finalized after signing, psbt: {}", psbt.serialize().as_hex());
	let ret = psbt.extract_tx().context("error extracting finalized tx from psbt")?;
	let txid = ret.compute_txid();
	let raw_tx = bitcoin::consensus::serialize(&ret);
	slog!(WalletSignedTx, wallet: "sweeper".into(), txid, raw_tx,
		inputs: ret.input.iter().map(|i| i.previous_output).collect(),
	);
	Ok(ret)
}

/// Build a sweep.
struct SweepBuilder<'a> {
	sweeper: &'a mut Process,
	sweeps: Vec<RoundSweepInput<'a>>,
	board_sweeps: Vec<BoardSweepInput>,
	feerate: FeeRate,
}

impl<'a> SweepBuilder<'a> {
	fn new(sweeper: &'a mut Process, feerate: FeeRate) -> Self {
		Self {
			sweeps: Vec::new(),
			board_sweeps: Vec::new(),
			sweeper, feerate,
		}
	}

	fn total_surplus(&self) -> Amount {
		self.board_sweeps.iter().map(|s| s.surplus(self.feerate).unwrap_or(Amount::ZERO))
			.chain(self.sweeps.iter().map(|s| s.surplus(self.feerate).unwrap_or(Amount::ZERO)))
			.sum()
	}

	fn total_nb_sweeps(&self) -> usize {
		self.sweeps.len() + self.board_sweeps.len()
	}

	/// Add sweep for the given vtxo tree output.
	fn add_vtxo_output(
		&mut self,
		round: &'a ExpiredRound,
		point: OutPoint,
		utxo: TxOut,
		agg_pk: XOnlyPublicKey,
	) {
		trace!("Adding vtxo sweep input {}", point);
		self.sweeps.push(RoundSweepInput {
			point, utxo, round,
			internal_key: agg_pk,
			sweep_meta: SweepMeta::Vtxo,
			weight: ark::tree::signed::NODE_SPEND_WEIGHT,
		});
	}

	/// Purge all sweeps sweeping the given utxo.
	fn purge_sweeps(&mut self, point: &OutPoint) {
		self.sweeps.retain(|s| {
			if s.point != *point {
				trace!("purging vtxo sweep for {} because successor tx confirmed", point);
				false
			} else {
				true
			}
		});
		self.board_sweeps.retain(|s| {
			if s.point != *point {
				trace!("purging board sweep for {} because successor tx confirmed", point);
				false
			} else {
				true
			}
		});
	}

	/// Purge all sweeps that are not economical at our configured feerate.
	fn purge_uneconomical(&mut self) {
		self.sweeps.retain(|s| {
			if s.surplus(self.feerate).is_none() {
				slog!(UneconomicalSweepInput, outpoint: s.point, value: s.amount());
				false
			} else {
				true
			}
		});
		self.board_sweeps.retain(|s| {
			if s.surplus(self.feerate).is_none() {
				slog!(UneconomicalSweepInput, outpoint: s.point, value: s.amount());
				false
			} else {
				true
			}
		});
	}


	/// Sweep the leftovers of the vtxo tree of the given round.
	///
	/// Returns the most recent of the confirmation heights for all sweep txs,
	/// [None] if there are unconfirmed transactions.
	async fn process_vtxos(&mut self, round: &'a ExpiredRound) -> anyhow::Result<Option<BlockHeight>> {
		// First check if the round tx is still available for sweeping, that'd be ideal.
		let tree_root = round.vtxo_txs.last().unwrap();
		let tree_root_txid = tree_root.compute_txid();

		let tree_root = self.sweeper.txindex.get_or_insert(
			tree_root_txid,
			|| tree_root.clone(),
		).await?;

		if !tree_root.confirmed() {
			trace!("Tree root tx {} not yet confirmed, sweeping round tx...", tree_root.txid);
			let point = OutPoint::new(round.id.as_round_txid(), ROUND_TX_VTXO_TREE_VOUT);
			if let Some((h, txid)) = self.sweeper.is_swept(point).await {
				trace!("Round tx vtxo tree output {point} is already swept \
					by us at height {h} with tx {txid}");
				return Ok(Some(h));
			} else {
				trace!("Sweeping round tx vtxo output {}", point);
				let utxo = round.round.funding_tx.output[0].clone();
				let agg_pk = round.round.signed_tree.spec.funding_tx_cosign_pubkey();
				self.add_vtxo_output(round, point, utxo, agg_pk);
				return Ok(None);
			}
		}

		// If the root is not available, we have to roll down the tree.
		//
		// The strategy we use is the following:
		// - we traverse the tree from root to leaves
		// - whenever a tx is confirmed
		//   - we remove from our to-sweep set all txs spending inputs from this tx
		//   - for each of its outputs
		//     - check whether a previous sweep tx confirmed
		//     - if not, we add the spend info to the set

		let mut ret = Some(0);
		let signed_txs = round.round.signed_tree.all_final_txs();
		let agg_pkgs = round.round.signed_tree.spec.cosign_agg_pks();
		for (signed_tx, agg_pk) in signed_txs.into_iter().zip(agg_pkgs).rev() {
			let txid = signed_tx.compute_txid();
			let tx = self.sweeper.txindex.get_or_insert(txid, || signed_tx.clone()).await?;
			if !tx.confirmed() {
				trace!("tx {} did not confirm yet, not sweeping", tx.txid);
				continue;
			}
			trace!("vtxo tree tx {} confirmed, prepping sweeps", tx.txid);

			// Purge sweeps of our tx's input.
			assert_eq!(1, signed_tx.input.len());
			self.purge_sweeps(&signed_tx.input[0].previous_output);

			for (idx, out) in signed_tx.output.into_iter().enumerate() {
				let point = OutPoint::new(tx.txid, idx as u32);
				if let Some((h, _txid)) = self.sweeper.is_swept(point).await {
					ret = ret.and_then(|old| Some(cmp::max(old, h)));
				} else {
					let utxo = out;
					self.add_vtxo_output(round, point, utxo, agg_pk);
					ret = None;
				}
			}
		}
		assert_ne!(ret, Some(0), "ret should have changed to something at least");
		Ok(ret)
	}

	async fn process_round(&mut self, round: &'a ExpiredRound, done_height: BlockHeight) -> anyhow::Result<()> {
		trace!("Processing vtxo tree for round {}", round.id);
		let vtxos_done = self.process_vtxos(round).await?;
		if vtxos_done.is_none() || vtxos_done.unwrap() > done_height {
			trace!("Pending vtxo sweeps for this round (height {:?}), waiting for {}",
				vtxos_done, done_height,
			);
			return Ok(());
		}

		//TODO(stevenroose) do this elsewhere
		slog!(RoundFullySwept, round_id: round.id);
		self.sweeper.round_finished(round).await;
		Ok(())
	}

	async fn create_tx(&mut self, tip: BlockHeight) -> anyhow::Result<Transaction> {
		let mut txb = self.sweeper.wallet.build_tx();
		txb.ordering(bdk_wallet::TxOrdering::Untouched);
		txb.current_height(tip);
		txb.manually_selected_only();

		for sweep in &self.sweeps {
			trace!("Adding round sweep: {}", sweep.point);
			txb.add_foreign_utxo_with_sequence(
				sweep.point,
				sweep.psbt(),
				sweep.weight,
				Sequence::ZERO,
			).expect("bdk rejected foreign utxo");
		}
		for sweep in &self.board_sweeps {
			trace!("Adding board sweep: {}", sweep.point);
			txb.add_foreign_utxo_with_sequence(
				sweep.point,
				sweep.psbt(),
				sweep.weight(),
				Sequence::ZERO,
			).expect("bdk rejected foreign utxo");
		}

		txb.drain_to(self.sweeper.drain_address.script_pubkey());
		txb.fee_rate(self.feerate);
		let mut psbt = txb.finish().expect("bdk failed to create round sweep tx");
		assert_eq!(psbt.inputs.len(), self.total_nb_sweeps(), "unexpected nb of inputs");

		// SIGNING

		psbt.try_sign_sweeps(&self.sweeper.server_key)?;
		Ok(finish_tx(&self.sweeper.wallet, psbt)?)
	}
}

struct Process {
	config: Config,
	bitcoind: BitcoinRpcClient,
	db: database::Db,
	txindex: TxIndex,
	tx_nursery: TxNursery,
	wallet: bdk_wallet::Wallet,
	server_key: Keypair,
	drain_address: Address,
	fee_estimator: Arc<FeeEstimator>,

	// runtime fields

	pending_txs: HashMap<Txid, txindex::Tx>,
	/// Pending txs indexed by the inputs they spend.
	pending_tx_by_utxo: HashMap<OutPoint, Vec<Txid>>,
}

impl Process {
	/// Store the tx in our local caches.
	fn store_pending(&mut self, tx: txindex::Tx) {
		for inp in &tx.tx.input {
			self.pending_tx_by_utxo.entry(inp.previous_output).or_insert(Vec::new()).push(tx.txid);
		}
		self.pending_txs.insert(tx.txid, tx);
	}

	/// Store the pending tx both in the db and mem cache.
	async fn add_new_pending(&mut self, txid: Txid, tx: Transaction) -> anyhow::Result<()> {
		self.db.store_pending_sweep(&txid, &tx).await
			.with_context(||
				format!("db error storing pending sweep, tx={}", serialize_hex(&tx)))?;

		let tx = self.tx_nursery.broadcast_tx(tx).await
			.context("Failed to broadcast sweeping transaction")?;

		self.store_pending(tx);
		Ok(())
	}

	async fn is_swept(&self, point: OutPoint) -> Option<(BlockHeight, Txid)> {
		if let Some(txs) = self.pending_tx_by_utxo.get(&point) {
			for txid in txs {
				let tx = self.pending_txs.get(txid).expect("broken: utxo but no tx");
				if let Some(block) = tx.status().confirmed_in() {
					return Some((block.height, tx.txid));
				}
			}
		}
		None
	}

	/// Clean up all artifacts after a round has been swept.
	async fn round_finished(&mut self, round: &ExpiredRound) {
		// round tx root
		self.pending_tx_by_utxo.remove(&OutPoint::new(round.id.as_round_txid(), ROUND_TX_VTXO_TREE_VOUT));

		// vtxo tree txs
		let vtxo_txs = round.round.signed_tree.all_final_txs();
		trace!("Removing vtxo txs from internal pending...");
		for tx in &vtxo_txs {
			for i in 0..tx.output.len() {
				self.pending_tx_by_utxo.remove(&OutPoint::new(tx.compute_txid(), i as u32));
			}
		}

		// connector txs
		trace!("Connector txs from internal pending...");
		for tx in round.connectors.iter_unsigned_txs() {
			for i in 0..tx.output.len() {
				self.pending_tx_by_utxo.remove(&OutPoint::new(tx.compute_txid(), i as u32));
			}
		}

		if let Err(e) = self.db.mark_round_swept(round.id).await {
			error!("Failed to remove round from db after successful sweeping: {}", e);
		}
	}

	async fn perform_sweep(&mut self) -> anyhow::Result<()> {
		let sweep_threshold = self.config.sweep_threshold;
		let tip = self.bitcoind.get_block_count()? as BlockHeight;

		let mut expired_rounds = Vec::new();
		for id in self.db.get_expired_round_ids(tip).await? {
			let round = self.db.get_round(id).await?.expect("db has round");
			expired_rounds.push(ExpiredRound::new(id, round));
		}
		trace!("{} expired rounds fetched", expired_rounds.len());
		telemetry::set_pending_expired_rounds_count(expired_rounds.len());

		let feerate = self.fee_estimator.regular();
		let mut builder = SweepBuilder::new(self, feerate);

		let done_height = tip - DEEPLY_CONFIRMED + 1;
		for round in &expired_rounds {
			trace!("Processing round {}", round.id);
			if let Err(err) = builder.process_round(round, done_height).await {
				warn!("Failed to add round {} to sweep_builder: {}", round.id, err);
			}
			builder.purge_uneconomical();
			//TODO(stevenroose) check if we exceeded some builder limits
		}

		// We processed all rounds, check if it's worth to sweep at all.
		let surplus = builder.total_surplus();
		trace!("Sweep surpus calculated: {}", surplus);
		if surplus < sweep_threshold {
			slog!(NotSweeping, available_surplus: surplus, nb_inputs: builder.total_nb_sweeps());
			return Ok(());
		}

		let sweep_points = builder.sweeps.iter().map(|s| s.point)
			.chain(builder.board_sweeps.iter().map(|s| s.point))
			.collect();
		slog!(SweepingVtxos, total_surplus: surplus, inputs: sweep_points);
		for s in &builder.sweeps {
			let tp = match s.sweep_meta {
				SweepMeta::Vtxo => "vtxo",
				SweepMeta::Connector(_) => "connector",
				SweepMeta::Board => unreachable!(),
			};
			slog!(SweepingOutput,
				outpoint: s.point,
				amount: s.amount(),
				sweep_type: tp.into(),
				surplus: s.surplus(feerate).unwrap(),
				expiry_height: s.round.round.expiry_height,
			);
		}
		for s in &builder.board_sweeps {
			slog!(SweepingOutput,
				outpoint: s.point,
				amount: s.amount(),
				sweep_type: "board".into(),
				surplus: s.surplus(feerate).unwrap(),
				expiry_height: s.vtxo_spec.expiry_height,
			);
		}

		let signed = builder.create_tx(tip).await.context("creating sweep tx")?;
		let txid = signed.compute_txid();
		self.add_new_pending(txid, signed.clone()).await?;
		slog!(SweepBroadcast, txid, surplus);

		Ok(())
	}

	async fn clear_confirmed_sweeps(&mut self) -> anyhow::Result<()> {
		let tip = self.bitcoind.tip()?;
		let mut to_remove = HashSet::new();
		for (txid, tx) in &self.pending_txs {
			if tx.tx.input.iter().any(|i| self.pending_tx_by_utxo.contains_key(&i.previous_output)) {
				trace!("tx {} still has pending sweep utxos", txid);
				continue;
			}

			if let Some(block) = tx.status().confirmed_in() {
				if tip.height - block.height >= 2 * DEEPLY_CONFIRMED {
					slog!(SweepTxFullyConfirmed, txid: *txid);
					self.db.confirm_pending_sweep(txid).await?;
				} else {
					slog!(SweepTxAbandoned,
						txid: *txid,
						tx: bitcoin::consensus::encode::serialize_hex(&tx.tx),
					);
					self.db.abandon_pending_sweep(txid).await?;
				}
			} else {
				slog!(SweepTxAbandoned,
					txid: *txid,
					tx: bitcoin::consensus::encode::serialize_hex(&tx.tx),
				);
				self.db.abandon_pending_sweep(txid).await?;
			}

			to_remove.insert(*txid);
		}
		for txid in to_remove {
			self.pending_txs.remove(&txid);
		}

		slog!(SweeperStats,
			nb_pending_txs: self.pending_txs.len(),
			nb_pending_utxos: self.pending_tx_by_utxo.len(),
		);

		let mut transaction_amount = 0;
		for tx in self.pending_txs.values() {
			transaction_amount += tx.tx.output_value().to_sat();
		}

		telemetry::set_pending_sweeper_stats(
			self.pending_txs.len(),
			transaction_amount,
			self.pending_tx_by_utxo.len(),
		);

		Ok(())
	}

	async fn run(
		mut self,
		mut ctrl_rx: mpsc::UnboundedReceiver<Ctrl>,
		rtmgr: RuntimeManager,
	) {
		info!("Starting VtxoSweeper...");
		let _worker = rtmgr.spawn_critical("VtxoSweeper");

		let mut timer = tokio::time::interval(self.config.round_sweep_interval);
		timer.reset();
		loop {
			tokio::select! {
				// Periodic interval for sweeping
				_ = timer.tick() => continue, //TODO remove this continue to re-enable
				Some(ctrl) = ctrl_rx.recv() => match ctrl {
					Ctrl::TriggerSweep => slog!(ReceivedSweepTrigger),
				},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting sweep loop...");
					break;
				},
			}

			//TODO(stevenroose) do this better
			// state.prune_confirmed().await;
			if let Err(e) = self.perform_sweep().await {
				warn!("Error during round processing: {}", e);
			}
			if let Err(e) = self.clear_confirmed_sweeps().await {
				warn!("Error occured in vtxo sweeper clear_confirmed_sweeps: {}", e);
			}

			timer.reset();
		}

		info!("VtxoSweeper terminated gracefully.");
	}
}

#[derive(Debug)]
enum Ctrl {
	TriggerSweep,
}

pub struct VtxoSweeper {
	ctrl_tx: mpsc::UnboundedSender<Ctrl>,
}

impl VtxoSweeper {
	pub async fn start(
		rtmgr: RuntimeManager,
		config: Config,
		network: Network,
		bitcoind: BitcoinRpcClient,
		db: database::Db,
		txindex: TxIndex,
		tx_nursery: TxNursery,
		server_key: Keypair,
		drain_address: Address,
		fee_estimator: Arc<FeeEstimator>,
	) -> anyhow::Result<Self> {
		let wallet = {
			// NB we don't need a wallet in the sweeper, but currently in BDK
			// the TxBuilder utility is only available on the Wallet type.
			// They are working on separating those, so we can get rid of this later.
			//TODO(stevenroose) drop wallet after BDK separates TxBuilder

			// randomly public key (skey: fb6c89300e9d5ed9fbc60e416ce5f58de971e689ab0d5d4d870f44c2bc48870f)
			let desc = "tr(035b5c42535be44af7c429b0e75f5bb6a999474ad10a4083d250676eff53832d9f)";
			bdk_wallet::Wallet::create_single(desc)
				.network(network)
				.create_wallet_no_persist()
				.expect("error creating bdk wallet")
		};

		let raw_pending = db.fetch_pending_sweeps().await
			.context("error fetching pending sweeps")?;

		let mut proc = Process {
			config, bitcoind, db, txindex, wallet, server_key, drain_address, tx_nursery,
			fee_estimator,
			pending_txs: HashMap::with_capacity(raw_pending.len()),
			pending_tx_by_utxo: HashMap::with_capacity(raw_pending.values().map(|t| t.input.len()).sum()),
		};

		for (_txid, raw_tx) in raw_pending {
			let tx = proc.tx_nursery.broadcast_tx(raw_tx).await
				.context("Failed to broadcast sweeping tx")?;
			proc.store_pending(tx);
		}

		let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel();
		tokio::spawn(proc.run(ctrl_rx, rtmgr));

		Ok(VtxoSweeper { ctrl_tx })
	}

	pub fn trigger_sweep(&self) -> anyhow::Result<()> {
		self.ctrl_tx.send(Ctrl::TriggerSweep).context("process down")?;
		Ok(())
	}
}
