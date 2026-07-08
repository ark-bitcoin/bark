
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bdk_wallet::{AddressInfo, TxBuilder, Wallet, WeightedUtxo};
use bdk_wallet::chain::{BlockId, CanonicalizationParams, ChainPosition, ConfirmationBlockTime};
use bdk_wallet::coin_selection::{
	decide_change, CoinSelectionAlgorithm, CoinSelectionResult, DefaultCoinSelectionAlgorithm,
	InsufficientFunds,
};
use bdk_wallet::error::CreateTxError;
use bitcoin::consensus::encode::{serialize, serialize_hex};
use bitcoin::{
	Amount, BlockHash, FeeRate, OutPoint, Script, Transaction, TxOut, Txid, Weight, Witness,
};
use bitcoin::psbt::{ExtractTxError, Input};
use log::{debug, trace};
use rand_core::RngCore;

use crate::TransactionExt;
use crate::cpfp::MakeCpfpFees;
use crate::fee::FEE_ANCHOR_SPEND_WEIGHT;

/// One canonical wallet tx, with its trust verdict already decided.
#[derive(Debug, Clone)]
pub struct LocalTransaction {
	/// Refcounted handle into BDK's in-memory tx graph; cloning is cheap.
	pub tx: Arc<Transaction>,
	pub chain_position: ChainPosition<ConfirmationBlockTime>,
	pub is_trusted: bool,
}

/// Borrowed view of one of our unspent outputs, returned by
/// [`TrustedCanonicalization::list_unspent`]. Carries the trust verdict
/// already decided for the creating tx so callers don't re-look-it-up.
pub struct TrustedUtxo<'a> {
	pub outpoint: OutPoint,
	pub txout: &'a TxOut,
	pub chain_position: &'a ChainPosition<ConfirmationBlockTime>,
	pub is_trusted: bool,
}

/// Single-pass canonical view of the wallet's tx graph with trust
/// verdicts pre-computed.
///
/// Built via one [`TxGraph::list_ordered_canonical_txs`] call which
/// yields txs in topological (parents-before-children) order. We mark
/// each tx trusted/untrusted in that order, so by the time we look at a
/// tx every ancestor is already decided — no recursion, no per-tx
/// `Wallet::get_tx`, no ancestor-walk budget heuristic.
///
/// In the same pass we also collect this wallet's UTXOs (ours-outpoints
/// from the keychain index, minus anything consumed by another canonical
/// tx). [`TrustedCanonicalization::list_unspent`] returns them without
/// triggering a second canonicalization the way [`Wallet::list_unspent`]
/// would.
///
/// [`TxGraph::list_ordered_canonical_txs`]: bdk_wallet::chain::TxGraph::list_ordered_canonical_txs
pub struct TrustedCanonicalization {
	txs: HashMap<Txid, LocalTransaction>,
	unspent: Vec<OutPoint>,
}

impl TrustedCanonicalization {
	/// Take one canonicalization snapshot of `w` and decide trust for
	/// every canonical tx using `min_confs` as the confirmation
	/// threshold.
	pub fn from_wallet(w: &Wallet, min_confs: u32) -> Self {
		let tip = w.latest_checkpoint().height();
		let chain = w.local_chain();
		let chain_tip = w.latest_checkpoint().block_id();

		let mut txs: HashMap<Txid, LocalTransaction> = HashMap::new();
		let mut spent: HashSet<OutPoint> = HashSet::new();

		for ctx in w.tx_graph().list_ordered_canonical_txs(
			chain, chain_tip, CanonicalizationParams::default(),
		) {
			let txid = ctx.tx_node.txid;
			let tx = ctx.tx_node.tx.clone();
			let chain_position = ctx.chain_position.clone();

			for input in tx.input.iter() {
				spent.insert(input.previous_output);
			}

			let nb_confs = match chain_position.confirmation_height_upper_bound() {
				Some(h) => tip.saturating_sub(h) + 1,
				None => 0,
			};
			let is_trusted = nb_confs >= min_confs || tx.input.iter().all(|input| {
				let prev = input.previous_output;
				let Some(prev_entry) = txs.get(&prev.txid) else { return false };
				let Some(prev_out) = prev_entry.tx.output.get(prev.vout as usize) else { return false };
				// Trust rule: this input must spend an output of ours,
				// AND the prev tx itself must already be trusted.
				// Topological order guarantees the prev entry is
				// fully decided.
				w.is_mine(prev_out.script_pubkey.clone()) && prev_entry.is_trusted
			});

			txs.insert(txid, LocalTransaction { tx, chain_position, is_trusted });
		}

		// Unspent = ours-outpoints (from the keychain index) ∩ canonical
		// txs ∖ spent. Mirrors `Wallet::list_unspent`'s use of
		// `spk_index().outpoints()` but reuses the canonical view we
		// just built instead of running a second canonicalization.
		let unspent = w.spk_index().outpoints().iter()
			.map(|(_, op)| *op)
			.filter(|op| !spent.contains(op))
			.filter(|op| txs.contains_key(&op.txid))
			.collect();

		Self { txs, unspent }
	}

	/// Trust verdict for `txid`. Unknown txids (not in the wallet's
	/// canonical view) are treated as untrusted.
	pub fn is_trusted(&self, txid: Txid) -> bool {
		self.txs.get(&txid).map(|e| e.is_trusted).unwrap_or(false)
	}

	/// Iterate this wallet's unspent outputs in canonical view, each
	/// carrying its trust verdict.
	pub fn list_unspent(&self) -> impl Iterator<Item = TrustedUtxo<'_>> + '_ {
		self.unspent.iter().map(move |op| {
			let lt = &self.txs[&op.txid];
			TrustedUtxo {
				outpoint: *op,
				txout: &lt.tx.output[op.vout as usize],
				chain_position: &lt.chain_position,
				is_trusted: lt.is_trusted,
			}
		})
	}
}

/// Balance categorized by our recursive trust model.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedBalance {
	/// Funds in UTXOs we trust (confirmed or all-ours unconfirmed chains).
	pub trusted: Amount,
	/// Funds in UTXOs we don't trust.
	pub untrusted: Amount,
}

impl TrustedBalance {
	pub fn total(&self) -> Amount {
		self.trusted + self.untrusted
	}
}

/// The [bdk_wallet::KeychainKind] that is always used, because we only use a single keychain.
pub const KEYCHAIN: bdk_wallet::KeychainKind = bdk_wallet::KeychainKind::External;


/// Coin selection for transactions whose only output is the drain (change) output, like a CPFP
/// child. Guarantees that this output ends up above the dust limit.
///
/// BDK's default algorithm stops selecting coins as soon as the target amount is covered. If the
/// selected coins overshoot the target by less than the dust limit, the leftover is too small to
/// be a valid output. Normally BDK would drop it and let it go to fees, but when the drain is the
/// transaction's only output, dropping it leaves no outputs at all, so `TxBuilder::finish` fails
/// with [InsufficientFunds] — even if the wallet has plenty of other coins available.
///
/// This wrapper asks the default algorithm for slightly more: the dust limit, plus the fee the
/// drain output itself adds. That makes it keep pulling in coins until the leftover is a valid
/// output. The result is then adjusted so that the extra ends up in the drain output rather than
/// being burned as fee.
#[derive(Debug, Clone, Copy, Default)]
pub struct NonDustDrainCoinSelection;

impl CoinSelectionAlgorithm for NonDustDrainCoinSelection {
	fn coin_select<R: RngCore>(
		&self,
		required_utxos: Vec<WeightedUtxo>,
		optional_utxos: Vec<WeightedUtxo>,
		fee_rate: FeeRate,
		target_amount: Amount,
		drain_script: &Script,
		rand: &mut R,
	) -> Result<CoinSelectionResult, InsufficientFunds> {
		// Fee cost of the drain output itself, computed exactly like bdk_wallet's `decide_change`
		// does: the leftover only becomes change after paying for the extra output, so selection
		// must cover that fee too. Zero when the caller uses an absolute fee, since BDK then
		// passes FeeRate::ZERO here.
		let drain_output_len = serialize(drain_script).len() + 8;
		let drain_output_fee = fee_rate
			* Weight::from_vb(drain_output_len as u64).expect("script length fits in Weight");
		let raise = drain_script.minimal_non_dust() + drain_output_fee;

		let mut result = DefaultCoinSelectionAlgorithm::default().coin_select(
			required_utxos, optional_utxos, fee_rate, target_amount + raise, drain_script, rand,
		)?;

		// The inner algorithm measured its leftover against the raised target, so it considers
		// the raise part of the fee. Recompute the leftover against the real target to hand the
		// raise back to the drain output. It is at least `raise`, so `decide_change` always
		// yields a non-dust `Excess::Change`.
		let remaining = result.selected_amount()
			.checked_sub(target_amount + result.fee_amount)
			.expect("selection covers the raised target");
		result.excess = decide_change(remaining, fee_rate, drain_script);
		Ok(result)
	}
}

/// An extension trait for [TxBuilder].
pub trait TxBuilderExt<'a, A>: BorrowMut<TxBuilder<'a, A>> {
	/// Add an input to the tx that spends a fee anchor.
	fn add_fee_anchor_spend(&mut self, anchor: OutPoint, output: &TxOut)
	where
		A: bdk_wallet::coin_selection::CoinSelectionAlgorithm,
	{
		let psbt_in = Input {
			witness_utxo: Some(output.clone()),
			final_script_witness: Some(Witness::new()),
			..Default::default()
		};
		self.borrow_mut().add_foreign_utxo(anchor, psbt_in, FEE_ANCHOR_SPEND_WEIGHT)
			.expect("adding foreign utxo");
	}
}
impl<'a, A> TxBuilderExt<'a, A> for TxBuilder<'a, A> {}

#[derive(Debug, thiserror::Error)]
pub enum CpfpInternalError {
	#[error("{0}")]
	General(String),
	#[error("Unable to construct transaction: {0}")]
	Create(CreateTxError),
	#[error("Unable to extract the final transaction after signing the PSBT: {0}")]
	Extract(ExtractTxError),
	#[error("Failed to determine the weight/fee when creating a P2A CPFP")]
	Fee(),
	#[error("Unable to finalize CPFP transaction: {0}")]
	FinalizeError(String),
	#[error("You need more confirmations on your on-chain funds: {0}")]
	InsufficientConfirmedFunds(InsufficientFunds),
	#[error("Transaction has no fee anchor: {0}")]
	NoFeeAnchor(Txid),
	#[allow(deprecated)]
	#[error("Unable to sign transaction: {0}")]
	Signer(bdk_wallet::signer::SignerError),
}

/// An extension trait for [Wallet].
pub trait WalletExt: BorrowMut<Wallet> {
	/// Peek into the next address.
	fn peek_next_address(&self) -> AddressInfo {
		self.borrow().peek_address(KEYCHAIN, self.borrow().next_derivation_index(KEYCHAIN))
	}

	/// Returns an iterator for each unconfirmed transaction in the wallet.
	fn unconfirmed_txids(&self) -> impl Iterator<Item = Txid> {
		self.borrow().transactions().filter_map(|tx| {
			if tx.chain_position.is_unconfirmed() {
				Some(tx.tx_node.txid)
			} else {
				None
			}
		})
	}

	/// Returns an iterator for each unconfirmed transaction in the wallet, useful for syncing
	/// with bitcoin core.
	fn unconfirmed_txs(&self) -> impl Iterator<Item = Arc<Transaction>> {
		self.borrow().transactions().filter_map(|tx| {
			if tx.chain_position.is_unconfirmed() {
				Some(tx.tx_node.tx.clone())
			} else {
				None
			}
		})
	}

	/// Compute the wallet balance using our recursive trust model.
	fn trusted_balance(&self, min_confs: u32) -> TrustedBalance {
		let canon = TrustedCanonicalization::from_wallet(self.borrow(), min_confs);
		let mut trusted = Amount::ZERO;
		let mut untrusted = Amount::ZERO;
		for utxo in canon.list_unspent() {
			if utxo.is_trusted {
				trusted += utxo.txout.value;
			} else {
				untrusted += utxo.txout.value;
			}
		}
		TrustedBalance { trusted, untrusted }
	}

	/// Return all UTXOs that are untrusted.
	fn untrusted_utxos(&self, min_confs: u32) -> Vec<OutPoint> {
		TrustedCanonicalization::from_wallet(self.borrow(), min_confs)
			.list_unspent()
			.filter(|u| !u.is_trusted)
			.map(|u| u.outpoint)
			.collect()
	}

	/// Check if a transaction is fully owned by the wallet (all inputs spend
	/// wallet-owned outputs).
	fn is_fully_owned_tx(&self, txid: Txid) -> bool {
		let wallet = self.borrow();
		let graph = wallet.tx_graph();
		match graph.get_tx(txid) {
			Some(tx) => {
				tx.input.iter().all(|input| {
					let prev = input.previous_output;
					graph.get_tx(prev.txid)
						.and_then(|prev_tx| prev_tx.output.get(prev.vout as usize).cloned())
						.map(|out| wallet.is_mine(out.script_pubkey))
						.unwrap_or(false)
					})
			}, None => false
		}

	}

	/// Insert a checkpoint into the wallet.
	///
	/// It's advised to use this only when recovering a wallet with a birthday.
	fn set_checkpoint(&mut self, height: u32, hash: BlockHash) {
		let checkpoint = BlockId { height, hash };
		let wallet = self.borrow_mut();
		wallet.apply_update(bdk_wallet::Update {
			chain: Some(wallet.latest_checkpoint().insert(checkpoint)),
			..Default::default()
		}).expect("should work, might fail if tip is genesis");
	}

	/// Mark the keys used in the outputs of this tx as unused
	///
	/// Used to replaced removed `cancel_tx` function as per suggestion:
	/// <https://github.com/bitcoindevkit/bdk_wallet/pull/393>
	fn mark_output_keys_unused(&mut self, tx: &Transaction) {
		let wallet = self.borrow_mut();
		for txout in &tx.output {
			if let Some((keychain, index)) = wallet.spk_index().index_of_spk(txout.script_pubkey.clone()) {
				// NOTE: unmark_used will **not** make something unused if it has actually been used
				// by a tx in the tracker. It only removes the superficial marking.
				wallet.unmark_used(*keychain, *index);
			}
		}
	}

	fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpInternalError> {
		let wallet = self.borrow_mut();
		let (fee_anchor_point, fee_anchor_txout) = tx.fee_anchor()
			.ok_or_else(|| CpfpInternalError::NoFeeAnchor(tx.compute_txid()))?;

		// Since BDK doesn't support adding extra weight for fees, we have to loop to achieve the
		// effective fee rate and potential minimum fee we need.
		let parent_weight = tx.weight();
		let extra_fee_needed = parent_weight * fees.effective();

		// Since BDK doesn't allow tx without recipients, we add a drain output.
		let change_addr = wallet.next_unused_address(KEYCHAIN);
		let dust_limit = change_addr.address.script_pubkey().minimal_non_dust();

		// We will loop, constructing the transaction and signing it until we exceed the effective
		// fee rate and meet any minimum fee requirements
		let mut final_child_weight = Weight::ZERO;
		let mut fee_needed = extra_fee_needed;
		for i in 0..100 {
			// We need to account for a particularly annoying BDK bug when using foreign UTXOs when
			// BDK tries to use the P2A value to pay the fees. If the P2A has a value of 420 sats
			// and the absolute fee is 200 sats, this will produce a 220 sat change output which
			// results in a coin selection error. Ideally, BDK would pull in an extra UTXO to ensure
			// the change output is more than the dust limit; however, this seems to be an edge case
			// with experimental foreign UTXOs.
			if fee_needed < fee_anchor_txout.value {
				if fee_anchor_txout.value - fee_needed < dust_limit {
					fee_needed = fee_anchor_txout.value + Amount::ONE_SAT;
				}
			}

			let mut b = wallet.build_tx();
			b.only_witness_utxo();
			b.exclude_unconfirmed();
			b.version(3); // for 1p1c package relay, all inputs must be confirmed
			b.add_fee_anchor_spend(fee_anchor_point, fee_anchor_txout);
			b.drain_to(change_addr.address.script_pubkey());
			b.fee_absolute(fee_needed);

			// Attempt to create and sign the transaction
			let mut psbt = b.finish().map_err(|e| match e {
				CreateTxError::CoinSelection(e) => CpfpInternalError::InsufficientConfirmedFunds(e),
				_ => CpfpInternalError::Create(e),
			})?;
			#[allow(deprecated)]
			let opts = bdk_wallet::SignOptions {
				trust_witness_utxo: true,
				..Default::default()
			};
			let finalized = wallet.sign(&mut psbt, opts)
				.map_err(|e| CpfpInternalError::Signer(e))?;
			if !finalized {
				return Err(CpfpInternalError::FinalizeError("finalization failed".into()));
			}
			let tx = psbt.extract_tx()
				.map_err(|e| CpfpInternalError::Extract(e))?;
			assert!(tx.input.iter().any(|i| i.previous_output == fee_anchor_point),
				"Missing anchor spend, tx is {}", serialize_hex(&tx),
			);

			// We can finally check the fees and weight
			let tx_weight = tx.weight();
			let total_weight = tx_weight + parent_weight;
			if tx_weight != final_child_weight {
				// Since the weight changed, we can drop the transaction and recalculate the
				// required fee amount.
				wallet.mark_output_keys_unused(&tx);
				final_child_weight = tx_weight;
				fee_needed = match fees {
					MakeCpfpFees::Effective(fr) => total_weight * fr,
					MakeCpfpFees::Rbf { min_effective_fee_rate, current_package_fee } => {
						// RBF requires that you spend at least the total fee of every
						// unconfirmed ancestor and the transaction you want to replace,
						// then you must add mintxrelayfee * package_vbytes on top.
						let min_tx_relay_fee = FeeRate::from_sat_per_vb(1).unwrap();
						let min_package_fee = current_package_fee +
							parent_weight * min_tx_relay_fee +
							tx_weight * min_tx_relay_fee;

						// This is the fee we want to pay based on the given minimum effective fee
						// rate. It's possible that the desired fee is lower than the minimum
						// package fee if the currently broadcast child transaction is bigger than
						// the transaction we just produced.
						let desired_fee = total_weight * min_effective_fee_rate;
						if desired_fee < min_package_fee {
							debug!("Using a minimum fee of {} instead of the desired fee of {} for RBF",
								min_package_fee, desired_fee,
							);
							min_package_fee
						} else {
							trace!("Attempting to use the desired fee of {} for CPFP RBF",
								desired_fee,
							);
							desired_fee
						}
					}
				}
			} else {
				debug!("Created P2A CPFP with weight {} and fee {} in {} iterations",
					total_weight, fee_needed, i,
				);
				return Ok(tx);
			}
		}
		Err(CpfpInternalError::General("Reached max iterations".into()))
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use bdk_wallet::KeychainKind;
	use bdk_wallet::chain::BlockId;
	use bdk_wallet::test_utils::{get_test_wpkh, insert_checkpoint, receive_output_in_latest_block};
	use bitcoin::Network;
	use bitcoin::hashes::Hash;

	/// A wallet with two confirmed UTXOs of 1000 and 1001 sats.
	fn two_utxo_wallet() -> (Wallet, OutPoint) {
		let mut wallet = Wallet::create_single(get_test_wpkh())
			.network(Network::Regtest)
			.create_wallet_no_persist()
			.unwrap();
		insert_checkpoint(&mut wallet, BlockId { height: 1_000, hash: BlockHash::all_zeros() });
		let op1 = receive_output_in_latest_block(&mut wallet, Amount::from_sat(1_000));
		receive_output_in_latest_block(&mut wallet, Amount::from_sat(1_001));
		(wallet, op1)
	}

	/// Build the drain-only tx shape of a CPFP child: one mandatory input, an absolute fee it
	/// covers on its own, and the drain as sole output. The 1000-sat input minus the 900-sat fee
	/// leaves 100 sats: below the change script's dust limit, so default coin selection fails
	/// (`InsufficientFunds`) instead of pulling in the second UTXO.
	#[test]
	fn non_dust_drain_selection_rescues_sub_dust_change() {
		let (mut wallet, op1) = two_utxo_wallet();
		let change_spk = wallet.reveal_next_address(KeychainKind::External)
			.address.script_pubkey();
		let fee = Amount::from_sat(900);
		assert!(Amount::from_sat(100) < change_spk.minimal_non_dust(), "premise");

		let mut b = wallet.build_tx().coin_selection(NonDustDrainCoinSelection);
		b.add_utxo(op1).unwrap();
		b.only_witness_utxo();
		b.drain_to(change_spk.clone());
		b.fee_absolute(fee);
		let psbt = b.finish().expect("both UTXOs cover fee + dust");

		let tx = &psbt.unsigned_tx;
		assert_eq!(tx.input.len(), 2, "must pull in the second UTXO");
		assert_eq!(tx.output.len(), 1);
		let change = tx.output[0].value;
		assert!(change >= change_spk.minimal_non_dust(), "change {} is dust", change);
		// The raised selection target must flow into the change, not the fee.
		assert_eq!(change, Amount::from_sat(2_001) - fee);
		assert_eq!(psbt.fee().unwrap(), fee);
	}

	/// When even the whole wallet can't leave a non-dust drain, selection must fail with
	/// [InsufficientFunds] instead of producing a dust (non-standard) output.
	#[test]
	fn non_dust_drain_selection_fails_when_change_can_only_be_dust() {
		let (mut wallet, op1) = two_utxo_wallet();
		let change_spk = wallet.reveal_next_address(KeychainKind::External)
			.address.script_pubkey();
		// Both UTXOs together hold 2001 sats; this fee leaves 101 sats, below the dust limit.
		let fee = Amount::from_sat(1_900);
		let dust = change_spk.minimal_non_dust();
		assert!(Amount::from_sat(101) < dust, "premise");

		let mut b = wallet.build_tx().coin_selection(NonDustDrainCoinSelection);
		b.add_utxo(op1).unwrap();
		b.only_witness_utxo();
		b.drain_to(change_spk);
		b.fee_absolute(fee);

		match b.finish() {
			Err(CreateTxError::CoinSelection(e)) => {
				assert_eq!(e.needed, fee + dust, "needed must cover fee plus a non-dust drain");
				assert_eq!(e.available, Amount::from_sat(2_001), "available must be the whole wallet");
			},
			other => panic!("expected InsufficientFunds, got {:?}", other),
		}
	}

	/// When a single UTXO leaves non-dust change, no extra input should be pulled in.
	#[test]
	fn non_dust_drain_selection_no_extra_input_when_change_is_fine() {
		let (mut wallet, op1) = two_utxo_wallet();
		let change_spk = wallet.reveal_next_address(KeychainKind::External)
			.address.script_pubkey();
		let fee = Amount::from_sat(500);

		let mut b = wallet.build_tx().coin_selection(NonDustDrainCoinSelection);
		b.add_utxo(op1).unwrap();
		b.only_witness_utxo();
		b.drain_to(change_spk);
		b.fee_absolute(fee);
		let psbt = b.finish().unwrap();

		let tx = &psbt.unsigned_tx;
		assert_eq!(tx.input.len(), 1, "1000-sat input alone leaves non-dust change");
		assert_eq!(tx.output[0].value, Amount::from_sat(500));
		assert_eq!(psbt.fee().unwrap(), fee);
	}
}

impl WalletExt for Wallet {}
