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
use std::sync::Arc;

use anyhow::Context;
use ark::rounds::RoundId;
use bitcoin::absolute::LockTime;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{
	psbt, sighash, Amount, FeeRate, OutPoint, Sequence, Transaction, TxOut, Txid, Weight,
};

use ark::{BlockHeight, BoardVtxo, VtxoSpec};
use ark::connectors::ConnectorChain;
use bitcoin_ext::TaprootSpendInfoExt;
use futures::StreamExt;

use crate::bitcoind::RpcApi;
use crate::database::model::StoredRound;
use crate::psbtext::{PsbtExt, PsbtInputExt, SweepMeta};
use crate::wallet::BdkWalletExt;
use crate::{txindex, App, DEEPLY_CONFIRMED, SECP};


struct BoardSweepInput {
	point: OutPoint,
	vtxo_spec: VtxoSpec,
}

impl BoardSweepInput {
	fn amount(&self) -> Amount {
		ark::board::board_amount(&self.vtxo_spec)
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
		let taproot = ark::board::board_taproot(&self.vtxo_spec);
		let utxo = TxOut {
			script_pubkey: ark::board::board_spk(&self.vtxo_spec),
			value: ark::board::board_amount(&self.vtxo_spec),
		};
		let mut ret = psbt::Input{
			witness_utxo: Some(utxo),
			sighash_type: Some(sighash::TapSighashType::Default.into()),
			tap_internal_key: Some(self.vtxo_spec.combined_pubkey()),
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
		let round_cosign_pk = self.round.round.signed_tree.spec.round_tx_cosign_pk();
		let taproot = self.round.round.signed_tree.spec.cosign_taproot(round_cosign_pk);
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
	fn new(id: RoundId, round: StoredRound) -> Self {
		Self {
			vtxo_txs: round.signed_tree.all_signed_txs(),
			connectors: ConnectorChain::new(
				round.nb_input_vtxos as usize,
				OutPoint::new(id.as_round_txid(), 1),
				round.connector_key.public_key(&*SECP),
			),
			id, round,
		}
	}
}

/// Build a sweep.
struct SweepBuilder<'a> {
	sweeper: &'a mut VtxoSweeper,
	sweeps: Vec<RoundSweepInput<'a>>,
	board_sweeps: Vec<BoardSweepInput>,
	feerate: FeeRate,
}

impl<'a> SweepBuilder<'a> {
	fn new(sweeper: &'a mut VtxoSweeper, feerate: FeeRate) -> Self {
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

	/// Add sweep for the given board output.
	fn add_board_output(&mut self, point: OutPoint, vtxo_spec: VtxoSpec) {
		trace!("Adding board sweep input {}", point);
		self.board_sweeps.push(BoardSweepInput { point, vtxo_spec });
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

	/// Add a sweep for the given connector output.
	fn add_connector_output(
		&mut self,
		round: &'a ExpiredRound,
		point: OutPoint,
		utxo: TxOut,
	) {
		trace!("Adding connector sweep input {}", point);
		self.sweeps.push(RoundSweepInput {
			point, utxo, round,
			internal_key: round.round.signed_tree.spec.asp_pk.x_only_public_key().0,
			sweep_meta: SweepMeta::Connector(round.round.connector_key),
			weight: ark::connectors::INPUT_WEIGHT,
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

	async fn process_board(&mut self, board: &BoardVtxo, done_height: BlockHeight) {
		let id = board.id();
		let exit_tx = board.exit_tx();
		let exit_txid = exit_tx.compute_txid();
		let exit_tx = self.sweeper.app.txindex.get_or_insert(&exit_txid, move || exit_tx).await;

		if !exit_tx.confirmed().await {
			if let Some((h, txid)) = self.sweeper.is_swept(board.onchain_output).await {
				trace!("Board {id} is already swept by us at height {h}");
				if h <= done_height {
					slog!(BoardFullySwept, board_utxo: board.onchain_output, sweep_tx: txid);
					self.sweeper.clear_board(board).await;
				}
			} else {
				trace!("Sweeping board vtxo {id}");
				self.add_board_output(board.onchain_output, board.spec.clone());
			}
		} else {
			trace!("User has broadcast board exit tx {} of board vtxo {id}", exit_txid);
			self.sweeper.clear_board(board).await;
		}
	}

	/// Sweep the leftovers of the vtxo tree of the given round.
	///
	/// Returns the most recent of the confirmation heights for all sweep txs,
	/// [None] if there are unconfirmed transactions.
	async fn process_vtxos(&mut self, round: &'a ExpiredRound) -> Option<BlockHeight> {
		// First check if the round tx is still available for sweeping, that'd be ideal.
		let tree_root = round.vtxo_txs.last().unwrap();
		let tree_root_txid = tree_root.compute_txid();
		let tree_root = self.sweeper.app.txindex.get_or_insert(&tree_root_txid, || {
			tree_root.clone()
		}).await;

		if !tree_root.confirmed().await {
			trace!("Tree root tx {} not yet confirmed, sweeping round tx...", tree_root.txid);
			let point = OutPoint::new(round.id.as_round_txid(), 0);
			if let Some((h, txid)) = self.sweeper.is_swept(point).await {
				trace!("Round tx vtxo tree output {point} is already swept \
					by us at height {h} with tx {txid}");
				return Some(h);
			} else {
				trace!("Sweeping round tx vtxo output {}", point);
				let utxo = round.round.tx.output[0].clone();
				let agg_pk = round.round.signed_tree.spec.round_tx_cosign_pk();
				self.add_vtxo_output(round, point, utxo, agg_pk);
				return None;
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
		let signed_txs = round.round.signed_tree.all_signed_txs();
		let agg_pkgs = round.round.signed_tree.spec.cosign_agg_pks();
		for (signed_tx, agg_pk) in signed_txs.into_iter().zip(agg_pkgs).rev() {
			let txid = signed_tx.compute_txid();
			let tx = self.sweeper.app.txindex.get_or_insert(&txid, || signed_tx.clone()).await;
			if !tx.confirmed().await {
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
		ret
	}

	/// Sweep the leftover connectors of the given round.
	///
	/// Returns the most recent of the confirmation heights for all sweep txs,
	/// [None] if there are unconfirmed transactions.
	async fn process_connectors(&mut self, round: &'a ExpiredRound) -> Option<BlockHeight> {
		// When it comes to connectors, we should have a single leftover output to sweep,
		// plus maybe some unused connector(s).

		// NB we don't really know the number of connectors, because we don't know the number
		// of inputs to the round. it doesn't matter, though, they are pre-signed, so
		// we can generate any chain of connector txs and check if the txs are on the chain or not
		let round_point = OutPoint::new(round.id.as_round_txid(), 1);
		let mut conn_txs = round.connectors.iter_unsigned_txs();

		let mut last = (round_point, round.round.tx.output[1].clone());
		let mut ret = Some(0);
		loop {
			let tx = match conn_txs.next() {
				None => return Some(0), // all connector txs confirmed and spent
				Some(c) => c,
			};

			let txid = tx.compute_txid();
			let tx = self.sweeper.app.txindex.get_or_insert(&txid, move || {
				error!("Txindex should have all connector txs. Missing {} for round {}",
					txid, round.id,
				);
				tx
			}).await;

			if tx.confirmed().await {
				// Check if the connector output is still unspent.
				let conn = OutPoint::new(tx.txid, 1);
				match self.sweeper.app.bitcoind.get_tx_out(&conn.txid, conn.vout, Some(true)) {
					Ok(Some(out)) => {
						if let Some((h, _txid)) = self.sweeper.is_swept(conn).await {
							ret = ret.and_then(|old| Some(cmp::max(old, h)));
						} else {
							let txout = TxOut {
								value: out.value,
								script_pubkey: out.script_pub_key.script().expect("invalid script"),
							};
							self.add_connector_output(round, conn, txout);
							ret = None;
						}
					},
					Ok(None) => {}, // ignore it
					Err(e) => {
						// we just try later
						error!("Error calling gettxout for connector utxo {}: {}", conn, e);
						return None;
					},
				}

				// Then continue the chain.
				last = (OutPoint::new(tx.txid, 0), tx.tx.output[0].clone());
			} else {
				// add the last point
				let (point, output) = last;
				if let Some((h, _txid)) = self.sweeper.is_swept(point).await {
					ret = ret.and_then(|old| Some(cmp::max(old, h)));
				} else {
					self.add_connector_output(round, point, output);
					ret = None;
				}
				break;
			}
		}
		assert_ne!(ret, Some(0), "ret should have changed to something at least");
		ret
	}

	async fn process_round(&mut self, round: &'a ExpiredRound, done_height: BlockHeight) {
		trace!("Processing vtxo tree for round {}", round.id);
		let vtxos_done = self.process_vtxos(round).await;
		if vtxos_done.is_none() || vtxos_done.unwrap() > done_height {
			trace!("Pending vtxo sweeps for this round (height {:?}), waiting for {}",
				vtxos_done, done_height,
			);
			return;
		}

		trace!("Processing connectors for round {}", round.id);
		let connectors_done = self.process_connectors(round).await;
		if connectors_done.is_none() || connectors_done.unwrap() > done_height {
			trace!("Pending connector sweeps for this round (height {:?}), waiting for {}",
				connectors_done, done_height,
			);
			return;
		}

		//TODO(stevenroose) do this elsewhere
		slog!(RoundFullySwept, round_id: round.id);
		self.sweeper.round_finished(round).await;
	}

	async fn create_tx(&self, tip: BlockHeight) -> anyhow::Result<Transaction> {
		let mut wallet = self.sweeper.app.wallet.lock().await;
		let drain_addr = wallet.reveal_next_address(bdk_wallet::KeychainKind::Internal).address;

		let mut txb = wallet.build_tx();
		txb.ordering(bdk_wallet::TxOrdering::Untouched);
		txb.nlocktime(LockTime::from_height(tip as u32).expect("actual height"));

		for sweep in &self.sweeps {
			txb.add_foreign_utxo_with_sequence(
				sweep.point,
				sweep.psbt(),
				sweep.weight,
				Sequence::ZERO,
			).expect("bdk rejected foreign utxo");
		}
		for sweep in &self.board_sweeps {
			txb.add_foreign_utxo_with_sequence(
				sweep.point,
				sweep.psbt(),
				sweep.weight(),
				Sequence::ZERO,
			).expect("bdk rejected foreign utxo");
		}

		txb.drain_to(drain_addr.script_pubkey());
		txb.fee_rate(self.feerate);
		let mut psbt = txb.finish().expect("bdk failed to create round sweep tx");
		assert_eq!(psbt.inputs.len(), self.total_nb_sweeps(), "unexpected nb of inputs");


		// SIGNING

		psbt.try_sign_sweeps(&self.sweeper.app.asp_key)?;
		let signed = wallet.finish_tx(psbt)?;
		wallet.persist(&self.sweeper.app.db).await?;
		Ok(signed)
	}
}


struct VtxoSweeper {
	app: Arc<App>,
	pending_txs: HashMap<Txid, txindex::Tx>,
	/// Pending txs indexed by the inputs they spend.
	pending_tx_by_utxo: HashMap<OutPoint, Vec<Txid>>,
}

impl VtxoSweeper {
	/// Store the tx in our local caches.
	fn store_pending(&mut self, tx: txindex::Tx) {
		for inp in &tx.tx.input {
			self.pending_tx_by_utxo.entry(inp.previous_output).or_insert(Vec::new()).push(tx.txid);
		}
		self.pending_txs.insert(tx.txid, tx);
	}

	/// Load the [VtxoSweeper] by loading all pending txs from the database.
	async fn load(app: Arc<App>) -> anyhow::Result<VtxoSweeper> {
		let raw_pending = app.db.fetch_pending_sweeps().await.context("error fetching pending sweeps")?;
		// Register all pending in the txindex.
		let mut ret = VtxoSweeper {
			app,
			pending_txs: HashMap::with_capacity(raw_pending.len()),
			pending_tx_by_utxo: HashMap::with_capacity(raw_pending.values().map(|t| t.input.len()).sum()),
		};

		for (_txid, raw_tx) in raw_pending {
			let tx = ret.app.txindex.broadcast_tx(raw_tx).await;
			ret.store_pending(tx);
		}

		Ok(ret)
	}

	/// Store the pending tx both in the db and mem cache.
	async fn add_new_pending(&mut self, txid: Txid, tx: Transaction) -> anyhow::Result<()> {
		self.app.db.store_pending_sweep(&txid, &tx).await.context("db error storing pending sweep")?;

		let tx = self.app.txindex.broadcast_tx(tx).await;
		self.store_pending(tx);
		Ok(())
	}

	async fn is_swept(&self, point: OutPoint) -> Option<(BlockHeight, Txid)> {
		if let Some(txs) = self.pending_tx_by_utxo.get(&point) {
			for txid in txs {
				let tx = self.pending_txs.get(txid).expect("broken: utxo but no tx");
				if let Some(h) = tx.status().await.confirmed_in() {
					return Some((h, tx.txid));
				}
			}
		}
		None
	}

	/// Clear the board data from our database because we either swept it, or the user
	/// has broadcast the exit tx, doing a unilateral exit.
	async fn clear_board(&mut self, board: &BoardVtxo) {
		if let Err(e) = self.app.db.mark_board_swept(board).await {
			error!("Failed to mark board vtxo {} as swept: {}", board.id(), e);
		}

		let reveal = board.exit_tx().compute_txid();
		self.app.txindex.unregister_batch(&[&board.onchain_output.txid, &reveal]).await;

		self.pending_tx_by_utxo.remove(&board.onchain_output);
	}

	/// Clean up all artifacts after a round has been swept.
	async fn round_finished(&mut self, round: &ExpiredRound) {
		// round tx root
		self.pending_tx_by_utxo.remove(&OutPoint::new(round.id.as_round_txid(), 0));
		self.pending_tx_by_utxo.remove(&OutPoint::new(round.id.as_round_txid(), 1));
		self.app.txindex.unregister(round.id.as_round_txid()).await;

		// vtxo tree txs
		let vtxo_txs = round.round.signed_tree.all_signed_txs();
		trace!("Removing vtxo txs from internal pending...");
		for tx in &vtxo_txs {
			for i in 0..tx.output.len() {
				self.pending_tx_by_utxo.remove(&OutPoint::new(tx.compute_txid(), i as u32));
			}
		}

		trace!("Removing vtxo txs from txindex...");
		self.app.txindex.unregister_batch(vtxo_txs.iter()).await;

		// connector txs
		trace!("Connector txs from internal pending...");
		for tx in round.connectors.iter_unsigned_txs() {
			for i in 0..tx.output.len() {
				self.pending_tx_by_utxo.remove(&OutPoint::new(tx.compute_txid(), i as u32));
			}
		}
		trace!("Removing connector txs from txindex...");
		self.app.txindex.unregister_batch(round.connectors.iter_unsigned_txs()).await;

		if let Err(e) = self.app.db.remove_round(round.id).await {
			error!("Failed to remove round from db after successful sweeping: {}", e);
		}
	}

	async fn perform_sweep(&mut self) -> anyhow::Result<()> {
		let sweep_threshold = self.app.config.sweep_threshold;
		let tip = self.app.bitcoind.get_block_count()? as BlockHeight;

		let mut expired_rounds = Vec::new();
		for id in self.app.db.get_expired_rounds(tip).await? {
			let round = self.app.db.get_round(id).await?.expect("db has round");
			expired_rounds.push(ExpiredRound::new(id, round));
		}
		trace!("{} expired rounds fetched", expired_rounds.len());

		let expired_boards = self.app.db
			.get_expired_boards(tip).await?
			.filter_map(|o| async { o.ok() })
			.collect::<Vec<_>>().await;
		trace!("{} expired boards fetched", expired_boards.len());

		let feerate = self.app.config.sweep_tx_fallback_feerate;
		let mut builder = SweepBuilder::new(self, feerate);

		let done_height = tip - DEEPLY_CONFIRMED + 1;
		for round in &expired_rounds {
			trace!("Processing round {}", round.id);
			builder.process_round(round, done_height).await;
			builder.purge_uneconomical();
			//TODO(stevenroose) check if we exceeded some builder limits
		}
		for board in &expired_boards {
			trace!("Processing board {}", board.id());
			builder.process_board(&board, done_height).await;
			builder.purge_uneconomical();
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
			slog!(SweepingOutput, outpoint: s.point, amount: s.amount(),
				surplus: s.surplus(feerate).unwrap(), sweep_type: tp.into(),
			);
		}
		for s in &builder.board_sweeps {
			slog!(SweepingOutput, outpoint: s.point, amount: s.amount(),
				surplus: s.surplus(feerate).unwrap(), sweep_type: "board".into(),
			);
		}

		let signed = builder.create_tx(tip).await.context("creating sweep tx")?;
		let txid = signed.compute_txid();
		self.add_new_pending(txid, signed.clone()).await?;
		slog!(SweepBroadcast, txid, surplus: surplus);

		Ok(())
	}

	async fn clear_confirmed_sweeps(&mut self) -> anyhow::Result<()> {
		let tip = self.app.bitcoind.get_block_count()?;
		let mut to_remove = HashSet::new();
		for (txid, tx) in &self.pending_txs {
			if tx.tx.input.iter().any(|i| self.pending_tx_by_utxo.contains_key(&i.previous_output)) {
				trace!("tx {} still has pending sweep utxos", txid);
				continue;
			}

			if let Some(h) = tx.status().await.confirmed_in() {
				if tip - h >= 2 * DEEPLY_CONFIRMED {
					slog!(SweepTxFullyConfirmed, txid: *txid);
				} else {
					slog!(SweepTxAbandoned, txid: *txid,
						tx: bitcoin::consensus::encode::serialize_hex(&tx.tx),
					);
				}
			} else {
				slog!(SweepTxAbandoned, txid: *txid,
					tx: bitcoin::consensus::encode::serialize_hex(&tx.tx),
				);
			}

			self.app.db.drop_pending_sweep(txid).await?;
			self.app.txindex.unregister(txid).await;
			to_remove.insert(*txid);
		}
		for txid in to_remove {
			self.pending_txs.remove(&txid);
		}
		slog!(SweeperStats, nb_pending_txs: self.pending_txs.len(),
			nb_pending_utxos: self.pending_tx_by_utxo.len(),
		);
		Ok(())
	}
}

/// Run a process that will periodically check for expired rounds and
/// sweep them into our internal wallet.
pub async fn run_vtxo_sweeper(
	app: Arc<App>,
	mut sweep_trigger_rx: tokio::sync::mpsc::Receiver<()>,
) -> anyhow::Result<()> {
	let mut shutdown = app.shutdown_channel.subscribe();

	let mut state = VtxoSweeper::load(app).await.context("failed to load VtxoSweeper state")?;

	info!("Starting expired vtxo sweep loop");
	loop {
		tokio::select! {
			// Periodic interval for sweeping
			() = tokio::time::sleep(state.app.config.round_sweep_interval) => {},
			// Trigger received via channel
			Some(()) = sweep_trigger_rx.recv() => slog!(ReceivedSweepTrigger),
			_ = shutdown.recv() => {
				info!("Shutdown signal received. Exiting sweep loop...");
				break;
			}
		}

		//TODO(stevenroose) do this better
		// state.prune_confirmed().await;
		if let Err(e) = state.perform_sweep().await {
			warn!("Error during round processing: {}", e);
		}
		if let Err(e) = state.clear_confirmed_sweeps().await {
			warn!("Error occured in vtxo sweeper clear_confirmed_sweeps: {}", e);
		}
	}

	info!("Expired vtxo sweep loop terminated gracefully.");

	Ok(())
}
