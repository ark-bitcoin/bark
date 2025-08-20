use bitcoin::{Amount, FeeRate, Txid};

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

/// Indicates how fees should be handled by when creating a CPFP
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MakeCpfpFees {
	/// Create a normal transaction with the given effective fee rate
	Effective(FeeRate),
	/// The transaction should be RBF compliant by meeting the given fee standards. The minimum fee
	/// does NOT include the RBF relay premium; it represents the total fees paid by the current
	/// transaction we seek to replace.
	Rbf { min_effective_fee_rate: FeeRate, package_fee: Amount },
}

impl MakeCpfpFees {
	pub fn effective(&self) -> FeeRate {
		match self {
			MakeCpfpFees::Effective(fr) => *fr,
			MakeCpfpFees::Rbf { min_effective_fee_rate, .. } => *min_effective_fee_rate,
		}
	}
}