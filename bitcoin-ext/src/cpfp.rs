use bitcoin::{Amount, FeeRate, Txid, Weight};

/// Returned by the bark API when creating a P2A CPFP transaction fails.
#[derive(Debug, thiserror::Error)]
pub enum CpfpError {
	#[error("Unable to create CPFP transaction: {0}")]
	CreateError(String),
	#[error("Unable to finalize CPFP transaction: {0}")]
	FinalizeError(String),
	#[error("You need more confirmations on your on-chain funds, {available} is available but {needed} is needed.")]
	InsufficientConfirmedFunds { needed: Amount, available: Amount },
	#[error("An internal error occurred while creating CPFP: {0}")]
	InternalError(String),
	#[error("Transaction has no fee anchor: {0}")]
	NoFeeAnchor(Txid),
	#[error("Unable to sign CPFP transaction: {0}")]
	SigningError(String),
	#[error("Unable to store CPFP transaction: {0}")]
	StoreError(String),
}

/// Indicates how fees should be handled by when creating a CPFP [bitcoin::Transaction].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MakeCpfpFees {
	/// Create a normal transaction with the given effective fee rate. If the new transaction spends
	/// a P2A (Pay-to-Anchor) output, then this represents the effective fee rate of the package as
	/// a whole, not just the child transaction.
	Effective(FeeRate),
	/// The intent is to replace a transaction already in the mempool so certain fee standards must
	/// be met.
	///
	/// See [BIP125](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki#implementation-details)
	/// for more details.
	Rbf {
		/// This represents the effective fee rate of the current transaction/package in the
		/// mempool. This must be exceeded by a new transaction. This also does not include bumping
		/// fees.
		min_effective_fee_rate: FeeRate,
		/// The current fee paid by the transaction/package to be replaced in the mempool. This must
		/// be exceeded by the new transaction.
		current_package_fee: Amount,
	},
}

impl MakeCpfpFees {
	pub fn effective(&self) -> FeeRate {
		match self {
			MakeCpfpFees::Effective(fr) => *fr,
			MakeCpfpFees::Rbf { min_effective_fee_rate, .. } => *min_effective_fee_rate,
		}
	}

	/// The fee a child of `child_weight` must pay for a zero-fee parent of `parent_weight`: the
	/// effective rate over the whole package, or for a replacement at least the replaced package's
	/// fee plus the minimum relay fee over the new package (BIP125).
	pub fn package_fee(&self, parent_weight: Weight, child_weight: Weight) -> Amount {
		let package_weight = parent_weight + child_weight;
		match self {
			MakeCpfpFees::Effective(fr) => package_weight * *fr,
			MakeCpfpFees::Rbf { min_effective_fee_rate, current_package_fee } => {
				let min_tx_relay_fee = FeeRate::from_sat_per_vb(1).unwrap();
				let min_package_fee = *current_package_fee +
					parent_weight * min_tx_relay_fee +
					child_weight * min_tx_relay_fee;
				(package_weight * *min_effective_fee_rate).max(min_package_fee)
			},
		}
	}
}