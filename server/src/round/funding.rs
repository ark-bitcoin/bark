//! Construction of a round's funding transaction.
//!
//! When a round needs multiple attempts, every attempt's funding tx must
//! share at least one input — the *pinned input* — with the previous
//! attempt. Once the last attempt confirms, clients who signed forfeits
//! on previous attempts have proof that those stale attempts can no
//! longer go on-chain.
//!
//! [`FundingTx`] keeps locks on every input it picked: the pinned input
//! is held across attempts, the extras are released when the
//! [`FundingTx`] is dropped.

use anyhow::Context;
use bitcoin::{Amount, FeeRate, OutPoint, Psbt, Transaction, TxOut, Txid};

use ark::rounds::ROUND_TX_VTXO_TREE_VOUT;

use crate::utils::InstrumentedLock;
use crate::wallet::{PersistedWallet, WalletUtxoGuard, WalletUtxosGuard};

/// Inputs needed to build a funding tx. Pass to [`FundingTxSpec::build`]
/// to produce a [`FundingTx`].
pub struct FundingTxSpec {
	/// The output in which the vtxo tree will be rooted.
	pub tree_output: TxOut,
	/// Fee rate for the funding tx.
	pub fee_rate: FeeRate,
	/// Confirmation threshold for trust: a UTXO is trusted once it (or any
	/// ancestor) reaches this many confirmations. Only trusted UTXOs are
	/// eligible as inputs for the funding tx.
	pub min_trusted_confs: u32,
	/// If `Some`, the wallet is forced to include this input in the new tx.
	/// `None` on the first attempt.
	pub pinned_input: Option<WalletUtxoGuard>,
}

impl FundingTxSpec {
	/// Build the funding tx, offloading the blocking work to the tokio
	/// blocking pool. Acquires the wallet lock internally and returns the
	/// guard alongside the resulting [`FundingTx`] so the caller can keep
	/// using the wallet (e.g. to sign and broadcast).
	pub async fn build(
		self,
		wallet: &InstrumentedLock<PersistedWallet>,
	) -> anyhow::Result<UnsignedFundingTx> {
		let mut wallet_lock = wallet.lock_owned().await;
		tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
			let funding_tx = self.compute_build(&mut wallet_lock)?;
			Ok(funding_tx)
		}).await
			.context("funding tx build task panicked")?
	}

	/// Build the funding tx synchronously. Blocks the calling thread on
	/// bdk's coin selection; in an async context prefer
	/// [`FundingTxSpec::build`].
	fn compute_build(self, wallet: &mut PersistedWallet) -> anyhow::Result<UnsignedFundingTx> {
		let start = std::time::Instant::now();


		let unavailable_outputs = wallet.unavailable_outputs(self.min_trusted_confs);

		let psbt = {
			let mut b = wallet.build_tx();
			// `Untouched` keeps insertion order: `tree_output` is added first, so
			// it lands at vout `ROUND_TX_VTXO_TREE_VOUT` (0), as the round tx requires.
			b.ordering(bdk_wallet::TxOrdering::Untouched);
			b.unspendable(unavailable_outputs);
			// NB: manual selection overrides unspendable
			if let Some(ref pinned) = self.pinned_input {
				b.add_utxo(pinned.utxo()).context("pinned input not in wallet")?;
			}
			b.add_recipient(self.tree_output.script_pubkey, self.tree_output.value);
			b.fee_rate(self.fee_rate);
			b.finish().context("bdk failed to build funding tx")?
		};

		// Determine the pinned input and collect the extras.
		let (pinned_input, extra_outpoints) = match self.pinned_input {
			Some(pinned) => {
				let extras = psbt.unsigned_tx.input.iter()
					.map(|i| i.previous_output)
					.filter(|o| *o != pinned.utxo())
					.collect::<Vec<_>>();
				(pinned, extras)
			},
			None => {
				let mut iter = psbt.unsigned_tx.input.iter().map(|i| i.previous_output);
				let pinned = iter.next()
					.expect("funded tx should have at least one input");
				let pinned = wallet.lock_wallet_utxo(pinned)
					.context("failed to lock pinned input")?;
				(pinned, iter.collect::<Vec<_>>())
			},
		};

		let _extra_inputs = wallet.lock_wallet_utxos(extra_outpoints)
			.context("failed to lock extra inputs")?;

		let txid = psbt.unsigned_tx.compute_txid();
		let total_output_amount = psbt.unsigned_tx.output.iter()
			.map(|o| o.value)
			.sum();
		slog!(RoundFundingTxBuilt,
			total_output_amount,
			pinned_input: pinned_input.utxo(),
			build_time: start.elapsed(),
		);
		Ok(UnsignedFundingTx { psbt, txid, pinned_input, _extra_inputs })
	}
}


/// A round's funding transaction with the lock guards on every input it
/// consumes. Built by [`FundingTxSpec::build`].
pub struct UnsignedFundingTx {
	psbt: Psbt,
	txid: Txid,
	pinned_input: WalletUtxoGuard,
	/// Held only for its Drop impl: releases the locks on the extra inputs
	/// when this `FundingTx` is dropped (e.g. on round restart).
	_extra_inputs: WalletUtxosGuard,
}

impl UnsignedFundingTx {
	pub fn psbt(&self) -> &Psbt {
		&self.psbt
	}

	/// The unsigned transaction.
	pub fn unsigned_tx(&self) -> &Transaction {
		&self.psbt.unsigned_tx
	}

	pub fn txid(&self) -> Txid {
		self.txid
	}

	/// The outpoint in which the vtxo tree is rooted (vout
	/// [`ROUND_TX_VTXO_TREE_VOUT`] of the funding tx).
	pub fn tree_outpoint(&self) -> OutPoint {
		OutPoint::new(self.txid, ROUND_TX_VTXO_TREE_VOUT)
	}

	pub fn fee(&self) -> Amount {
		self.psbt.fee().expect("freshly built psbt has a valid fee")
	}

	/// Consume `self`, releasing the lock on every extra input and returning
	/// the guard for the pinned one. Used between round attempts: we keep
	/// the pinned input locked, but free the rest so the wallet can pick
	/// again on the next attempt.
	pub fn into_pinned_input(self) -> WalletUtxoGuard {
		self.pinned_input
	}

	pub fn sign(self, wallet: &mut PersistedWallet) -> anyhow::Result<SignedFundingTx> {
		match wallet.finish_tx(self.psbt().clone()) {
			Ok(tx) => Ok(SignedFundingTx {
				tx,
				txid: self.txid,
				fee: self.fee(),
				pinned_input: self.pinned_input,
				_extra_inputs: self._extra_inputs,
			}),
			Err(e) => bail!("Failed to sign funding transaction: {:?}", e),
		}
	}
}

pub struct SignedFundingTx {
	pub tx: Transaction,
	pub txid: Txid,
	pub fee: Amount,
	pub pinned_input: WalletUtxoGuard,
	/// Held only for its Drop impl: releases the locks on the extra inputs
	/// when this `FundingTx` is dropped (e.g. on round restart).
	pub _extra_inputs: WalletUtxosGuard,
}





