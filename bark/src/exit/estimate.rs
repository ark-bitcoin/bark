//! Fee estimation for emergency (unilateral) exits.
//!
//! Exiting a VTXO unilaterally has two distinct onchain costs:
//!
//! - **exit broadcast**: every not-yet-confirmed transaction in the VTXO's tree chain is a
//!   zero-fee transaction carrying a P2A anchor, so each must be CPFP-bumped to confirm. This is
//!   the dominant, time-critical cost and is funded from the wallet's confirmed onchain UTXOs.
//! - **claim/drain**: once the exit outputs mature past their CSV delta they are swept to an
//!   onchain address with a single batched transaction whose fee comes out of the recovered value.
//!
//! [`Exit::estimate_emergency_exit_fee`] reports both as a breakdown for a set of VTXOs, reflecting
//! the current chain state (already-confirmed tree transactions cost nothing).

use bitcoin::transaction::{predict_weight, InputWeightPrediction};
use bitcoin::{
	Address, Amount, FeeRate, Sequence, Transaction, TxIn, TxOut, Weight, Witness, ScriptBuf,
	sighash,
};
use bitcoin::secp256k1::{Secp256k1, SecretKey};

use ark::Vtxo;
use ark::vtxo::Full;
use ark::vtxo::policy::signing::VtxoSigner;

use ark::VtxoId;

use crate::Wallet;
use crate::exit::{Exit, ExitError};

/// A breakdown of the estimated onchain cost of unilaterally exiting a set of VTXOs.
///
/// `exit_broadcast_fee` is paid now from confirmed onchain funds; `claim_fee` is paid later
/// out of the recovered value. Use [ExitFeeEstimate::total] for the sum. See `fee_rate` for how
/// each leg is priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitFeeEstimate {
	/// The total fees required to broadcast every not-yet-confirmed exit transaction.
	///
	/// This is the minimum offchain-balance required to pay for an emergency exit.
	pub exit_broadcast_fee: Amount,
	/// Fee for transaction that drains the exit outputs. It is substracted from
	/// the exited VTXO amount.
	pub claim_fee: Amount,
	/// The fee rate used to price the exit-broadcast (CPFP) leg. Unless an explicit fee rate was
	/// supplied, the claim leg is priced separately at the chain's `regular` rate, so this is not
	/// necessarily the rate behind `claim_fee`.
	pub fee_rate: FeeRate,
	/// The number of exit transactions that still need to be broadcast and CPFP-bumped.
	pub txs_to_broadcast: usize,
	/// Whether the wallet's current confirmed onchain balance covers the full exit-broadcast walk.
	///
	/// A unilateral exit is funded serially across confirmed UTXOs (a CPFP child can only spend
	/// confirmed coins, so each bump's change must confirm before it can fund the next one). An
	/// exit can therefore stall midway if confirmed funds run short even when a single per-step fee
	/// looks affordable. The walk is simulated bump by bump against a replica of the wallet;
	/// `false` means confirmed funds ran out partway through it.
	pub fundable: bool,
}

impl ExitFeeEstimate {
	/// The total estimated cost: `exit_broadcast_fee + claim_fee`.
	pub fn total(&self) -> Amount {
		self.exit_broadcast_fee + self.claim_fee
	}
}

impl Exit {
	/// Estimate the onchain fees needed to unilaterally exit the given VTXOs.
	///
	/// The result takes the current chain state into account: any exit transactions
	/// that are already confirmed onchain have no extra cost.
	///
	/// # Parameters
	///  - `fee_rate` applies to both the broadcast and claim. If not provided, the
	/// broadcast txs will use *fast* fee rate, and the claim one will use the *regular*
	/// rate.
	///  - `destination` influences only the claim transaction weight. If not set, a dummy P2TR address
	/// for the wallet's network is used.
	///
	/// # Errors
	/// - [ExitError::UnknownVtxo] if a VTXO id isn't known to the wallet.
	/// - [ExitError::DustLimit] if a VTXO is below the dust limit (it can't be exited).
	/// - [ExitError::VtxoAlreadyExited] if a VTXO has already completed its exit.
	/// - [ExitError::VtxoAlreadySpent] if a VTXO was already spent (e.g. forfeited in a round).
	pub async fn estimate_emergency_exit_fee(
		&self,
		vtxos: &[VtxoId],
		wallet: &Wallet,
		fee_rate: Option<FeeRate>,
		destination: Option<Address>,
	) -> anyhow::Result<ExitFeeEstimate, ExitError> {
		let (broadcast_fee_rate, claim_fee_rate) = match fee_rate {
			Some(fr) => (fr, fr),
			None => (
				self.default_exit_fee_rate().await,
				wallet.chain().fee_rates().await.regular,
			),
		};

		// Resolve each VTXO into the exit transactions that still need broadcasting (already-
		// confirmed ones cost nothing) plus the full VTXOs we'll drain.
		let exits = self.collect_unconfirmed_exit_parents(vtxos).await?;
		let mut unconfirmed_parents = Vec::new();
		let mut full_vtxos = Vec::with_capacity(exits.len());
		for exit in exits {
			// Packages already in the mempool at a sufficient feerate need no new child.
			unconfirmed_parents.extend(exit.parents.into_iter().filter_map(|(tx, child)| {
				child.required_cpfp_fees(broadcast_fee_rate).map(|fees| (tx, fees))
			}));
			full_vtxos.push(exit.vtxo);
		}

		// CPFP-bump every unconfirmed exit transaction.
		let txs_to_broadcast = unconfirmed_parents.len();
		let (children, fundable) = match wallet.onchain() {
			Some(onchain) => {
				let walk = onchain.read().await
					.estimate_p2a_cpfp_walk(&unconfirmed_parents)
					.map_err(|e| ExitError::InternalError { error: e.to_string() })?;

				// The walk funds each child from confirmed coins, recycling change exactly like the real
				// serial broadcast, so it completing is the precise version of "the confirmed balance
				// covers the whole walk".
				let fundable = walk.shortfall.is_none();

				(walk.children, fundable)
			},
			None => (vec![], false)
		};

		let mut exit_broadcast_fee = children.iter().map(|(_, fee)| *fee).sum::<Amount>();
		// The walk stops when confirmed funds run out; each remaining parent is then priced with
		// a canonical one-input P2TR-funded child at the requested rate.
		for (parent, _) in unconfirmed_parents.iter().skip(children.len()) {
			exit_broadcast_fee += broadcast_fee_rate * (parent.weight() + canonical_cpfp_child_weight());
		}

		// a single batched drain of every VTXO to one destination.
		let claim_fee = self.estimate_claim_fee(&full_vtxos, wallet, claim_fee_rate, destination).await?;

		Ok(ExitFeeEstimate {
			exit_broadcast_fee,
			claim_fee,
			fee_rate: broadcast_fee_rate,
			txs_to_broadcast,
			fundable,
		})
	}

	/// Builds the batched drain transaction for the given VTXOs and returns `fee_rate * weight`.
	///
	/// Mirrors the weight path of [Exit::drain_exits] but signs through the wallet's [VtxoSigner]
	/// directly, since VTXOs are most often not claimable yet when estimating.
	async fn estimate_claim_fee(
		&self,
		vtxos: &[Vtxo<Full>],
		wallet: &Wallet,
		fee_rate: FeeRate,
		destination: Option<Address>,
	) -> anyhow::Result<Amount, ExitError> {
		if vtxos.is_empty() {
			return Ok(Amount::ZERO);
		}

		let address = match destination {
			Some(a) => a,
			None => placeholder_p2tr_address(wallet).await?,
		};

		let tip = wallet.chain().tip().await
			.map_err(|e| ExitError::TipRetrievalFailure { error: e.to_string() })?;
		let locktime = tip.to_locktime()
			.map_err(|e| ExitError::InvalidLocktime { tip, error: e.to_string() })?;

		let mut output_amount = Amount::ZERO;
		let mut tx_ins = Vec::with_capacity(vtxos.len());
		for vtxo in vtxos {
			let clause = wallet.find_signable_clause(vtxo).await
				.ok_or(ExitError::ClaimMissingSignableClause { vtxo: vtxo.id() })?;
			output_amount += vtxo.amount();
			tx_ins.push(TxIn {
				previous_output: vtxo.point(),
				script_sig: ScriptBuf::default(),
				sequence: clause.sequence().unwrap_or(Sequence::ZERO),
				witness: Witness::new(),
			});
		}

		let mut tx = Transaction {
			version: bitcoin::transaction::Version::TWO,
			lock_time: locktime,
			input: tx_ins,
			output: vec![TxOut { script_pubkey: address.script_pubkey(), value: output_amount }],
		};

		// Sign each input to get a correctly-sized witness, then read off the weight. Signing
		// borrows the transaction, so collect the witnesses first and apply them afterwards.
		let prevouts = vtxos.iter().map(|v| v.txout()).collect::<Vec<_>>();
		let prevouts = sighash::Prevouts::All(&prevouts);
		let mut witnesses = Vec::with_capacity(vtxos.len());
		{
			let mut shc = sighash::SighashCache::new(&tx);
			for (i, vtxo) in vtxos.iter().enumerate() {
				let witness = wallet.sign_input(vtxo, i, &mut shc, &prevouts).await
					.map_err(|e| ExitError::ClaimSigningError { error: e.to_string() })?;
				witnesses.push(witness);
			}
		}
		for (input, witness) in tx.input.iter_mut().zip(witnesses) {
			input.witness = witness;
		}

		Ok(fee_rate * tx.weight())
	}
}

/// The weight of a canonical CPFP child: one P2A anchor input, one P2TR key-spend funding input,
/// and one P2TR change output.
fn canonical_cpfp_child_weight() -> Weight {
	const P2TR_SPK_LEN: usize = 34;
	predict_weight(
		[
			// P2A anchor spend: empty scriptSig, empty witness.
			InputWeightPrediction::new(0, [0usize; 0]),
			InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
		],
		[P2TR_SPK_LEN],
	)
}

/// A throwaway P2TR address on the wallet's network, used only to weigh the drain output.
async fn placeholder_p2tr_address(wallet: &Wallet) -> anyhow::Result<Address, ExitError> {
	let network = wallet.network().await
		.map_err(|e| ExitError::InternalError { error: e.to_string() })?;
	let secp = Secp256k1::new();
	let sk = SecretKey::from_slice(&[1u8; 32]).expect("valid secret key");
	let (xonly, _) = sk.public_key(&secp).x_only_public_key();
	Ok(Address::p2tr(&secp, xonly, None, network))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn canonical_child_weight_is_plausible() {
		// A 2-input (anchor + P2TR key spend), 1-P2TR-output v3 child is on the order of
		// ~110-160 vbytes; assert we land in a sane band rather than e.g. zero or a wild value.
		let w = canonical_cpfp_child_weight();
		assert!(w > Weight::from_vb_unchecked(90), "child weight too small: {}", w);
		assert!(w < Weight::from_vb_unchecked(200), "child weight too large: {}", w);
	}
}
