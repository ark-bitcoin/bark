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

/// The default safety margin applied to the exit-broadcast fee estimate.
///
/// Covers feerate movement between estimating and exiting, and UTXO consolidation making the
/// real CPFP children heavier than the canonical single-input child used for pricing.
pub const DEFAULT_BROADCAST_FEE_MARGIN: f64 = 1.2;

/// A breakdown of the estimated onchain cost of unilaterally exiting a set of VTXOs.
///
/// `exit_broadcast_fee` is paid now from confirmed onchain funds; `claim_fee` is paid later
/// out of the recovered value. Use [ExitFeeEstimate::total] for the sum. See `fee_rate` for how
/// each leg is priced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitFeeEstimate {
	/// The total fees required to broadcast every not-yet-confirmed exit transaction, including
	/// the fee margin — deliberately above `fee_rate × weight`.
	///
	/// The onchain balance to fund the exit with at the chosen margin; the unscaled fee is the
	/// floor below which the exit cannot complete.
	pub exit_broadcast_fee: Amount,
	/// Fee for transaction that drains the exit outputs. It is substracted from
	/// the exited VTXO amount.
	pub claim_fee: Amount,
	/// The fee rate used to price the exit-broadcast (CPFP) leg, before the fee margin. Unless an
	/// explicit fee rate was supplied, the claim leg is priced separately at the chain's `regular`
	/// rate, so this is not necessarily the rate behind `claim_fee`.
	pub fee_rate: FeeRate,
	/// The number of exit transactions that still need to be broadcast and CPFP-bumped.
	pub txs_to_broadcast: usize,
}

impl ExitFeeEstimate {
	/// The total estimated cost: `exit_broadcast_fee + claim_fee`, kept within
	/// [Amount::MAX_MONEY] by [Exit::estimate_emergency_exit_fee].
	pub fn total(&self) -> Amount {
		self.exit_broadcast_fee + self.claim_fee
	}
}

impl Exit {
	/// Estimate the onchain fees needed to unilaterally exit the given VTXOs.
	///
	/// The result takes the current chain state into account: any exit transactions
	/// that are already confirmed onchain have no extra cost. The estimate is pure weight
	/// arithmetic — it never touches the onchain wallet, so it can be taken before the wallet
	/// holds any funds.
	///
	/// # Parameters
	///  - `fee_rate` applies to both the broadcast and claim. If not provided, the
	/// broadcast txs will use *fast* fee rate, and the claim one will use the *regular*
	/// rate.
	///  - `destination` influences only the claim transaction weight. If not set, a dummy P2TR address
	/// for the wallet's network is used.
	///  - `fee_margin` scales the broadcast leg, defaulting to [DEFAULT_BROADCAST_FEE_MARGIN].
	/// Must be finite and non-negative.
	///
	/// # Errors
	/// - [ExitError::InvalidFeeMargin] if `fee_margin` is not finite and non-negative, or scales
	///   the fee out of range.
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
		fee_margin: Option<f64>,
	) -> anyhow::Result<ExitFeeEstimate, ExitError> {
		let fee_margin = fee_margin.unwrap_or(DEFAULT_BROADCAST_FEE_MARGIN);
		if !fee_margin.is_finite() || fee_margin < 0.0 {
			return Err(ExitError::InvalidFeeMargin { margin: fee_margin.to_string() });
		}

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
		let mut txs_to_broadcast = 0;
		let mut exit_broadcast_fee = Amount::ZERO;
		let mut full_vtxos = Vec::with_capacity(exits.len());
		for exit in exits {
			for (parent, child) in &exit.parents {
				// Packages already in the mempool at a sufficient feerate cost nothing extra.
				let Some(fees) = child.required_cpfp_fees(broadcast_fee_rate) else {
					continue;
				};
				let fee = fees.package_fee(parent.weight(), canonical_cpfp_child_weight());
				exit_broadcast_fee = exit_broadcast_fee.checked_add(fee)
					.filter(|total| *total <= Amount::MAX_MONEY)
					.ok_or_else(|| ExitError::InternalError {
						error: format!("exit broadcast fee exceeds {}", Amount::MAX_MONEY),
					})?;
				txs_to_broadcast += 1;
			}
			full_vtxos.push(exit.vtxo);
		}
		let scaled = (exit_broadcast_fee.to_sat() as f64 * fee_margin).ceil();
		if scaled > Amount::MAX_MONEY.to_sat() as f64 {
			return Err(ExitError::InvalidFeeMargin { margin: fee_margin.to_string() });
		}
		let exit_broadcast_fee = Amount::from_sat(scaled as u64);

		// a single batched drain of every VTXO to one destination.
		let claim_fee = self.estimate_claim_fee(&full_vtxos, wallet, claim_fee_rate, destination).await?;
		if exit_broadcast_fee.checked_add(claim_fee).is_none_or(|total| total > Amount::MAX_MONEY) {
			return Err(ExitError::InvalidFeeMargin { margin: fee_margin.to_string() });
		}

		Ok(ExitFeeEstimate {
			exit_broadcast_fee,
			claim_fee,
			fee_rate: broadcast_fee_rate,
			txs_to_broadcast,
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
