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

/// The incremental relay fee to assume when the node's isn't known: 1 sat/vB, the highest
/// default Bitcoin Core has used for `-incrementalrelayfee`.
pub const DEFAULT_INCREMENTAL_RELAY_FEE: FeeRate = FeeRate::from_sat_per_kwu(250);

/// Indicates how fees should be handled by when creating a CPFP [bitcoin::Transaction].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MakeCpfpFees {
	/// Create a normal transaction with the given effective fee rate. If the new transaction spends
	/// a P2A (Pay-to-Anchor) output, then this represents the effective fee rate of the package as
	/// a whole, not just the child transaction.
	Effective(FeeRate),
	/// Replace transactions in the mempool: what spends the parent's anchor, typically an
	/// earlier CPFP child, or, if the parent isn't in the mempool yet, what conflicts with it.
	///
	/// The replacement is the new child, or the whole package when the parent is new too. It
	/// pays at least the replaced fee plus the incremental relay fee over its own weight, and a
	/// feerate above the replaced one by the incremental relay fee, so bitcoind accepts it (see
	/// [BIP125](https://github.com/bitcoin/bips/blob/master/bip-0125.mediawiki#implementation-details)).
	Rbf {
		/// The effective fee rate the new package must reach.
		min_effective_fee_rate: FeeRate,
		/// The total fee of the transactions the new child replaces.
		replaced_fee: Amount,
		/// The fee rate of the transactions the new child replaces.
		replaced_fee_rate: FeeRate,
		/// The node's `-incrementalrelayfee`, see [DEFAULT_INCREMENTAL_RELAY_FEE].
		incremental_relay_fee: FeeRate,
		/// Whether the parent is already in the mempool. If not, it is part of the replacement.
		parent_in_mempool: bool,
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
	/// effective rate over the whole package, and for a replacement whatever the replacement
	/// rules require on top.
	pub fn package_fee(&self, parent_weight: Weight, child_weight: Weight) -> Amount {
		let effective = (parent_weight + child_weight) * self.effective();
		match self {
			MakeCpfpFees::Effective(_) => effective,
			MakeCpfpFees::Rbf {
				replaced_fee, replaced_fee_rate, incremental_relay_fee, parent_in_mempool, ..
			} => {
				// Bitcoind charges the replacement per vbyte of each tx, rounded up.
				let replacement_vsize = if *parent_in_mempool {
					child_weight.to_vbytes_ceil()
				} else {
					parent_weight.to_vbytes_ceil() + child_weight.to_vbytes_ceil()
				};
				let min_fee = *replaced_fee + fee_ceil(*incremental_relay_fee, replacement_vsize);
				let min_fee_rate = FeeRate::from_sat_per_kwu(replaced_fee_rate.to_sat_per_kwu()
					.saturating_add(incremental_relay_fee.to_sat_per_kwu()));
				effective.max(min_fee).max(fee_ceil(min_fee_rate, replacement_vsize))
			},
		}
	}
}

/// The fee at `fee_rate` for `vsize` vbytes, rounded up.
fn fee_ceil(fee_rate: FeeRate, vsize: u64) -> Amount {
	let sat_per_kvb = fee_rate.to_sat_per_kwu().saturating_mul(4);
	Amount::from_sat(sat_per_kvb.saturating_mul(vsize).div_ceil(1000))
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn rbf_package_fee_follows_the_replacement_rules() {
		let parent = Weight::from_vb_unchecked(200);
		let child = Weight::from_vb_unchecked(100);
		let incremental_relay_fee = FeeRate::from_sat_per_vb_u32(1);
		let rbf = |min_effective, replaced_fee, replaced_fee_rate| MakeCpfpFees::Rbf {
			min_effective_fee_rate: FeeRate::from_sat_per_vb_u32(min_effective),
			replaced_fee: Amount::from_sat(replaced_fee),
			replaced_fee_rate: FeeRate::from_sat_per_vb_u32(replaced_fee_rate),
			incremental_relay_fee,
			parent_in_mempool: true,
		};

		// The effective rate over the package decides.
		assert_eq!(rbf(10, 1_000, 2).package_fee(parent, child), Amount::from_sat(3_000));
		// Outbid a large replaced fee by the incremental relay fee over the child.
		assert_eq!(rbf(10, 9_000, 9).package_fee(parent, child), Amount::from_sat(9_100));
		// Outbid the replaced feerate by the incremental relay fee.
		assert_eq!(rbf(10, 1_000, 40).package_fee(parent, child), Amount::from_sat(4_100));
	}

	#[test]
	fn rbf_package_fee_counts_a_new_parent_as_replacement() {
		let parent = Weight::from_vb_unchecked(200);
		let child = Weight::from_vb_unchecked(200);
		let fees = |parent_in_mempool| MakeCpfpFees::Rbf {
			min_effective_fee_rate: FeeRate::from_sat_per_vb_u32(1),
			replaced_fee: Amount::from_sat(9_000),
			replaced_fee_rate: FeeRate::from_sat_per_vb_u32(1),
			incremental_relay_fee: FeeRate::from_sat_per_vb_u32(5),
			parent_in_mempool,
		};

		// Only the child is new.
		assert_eq!(fees(true).package_fee(parent, child), Amount::from_sat(10_000));
		// The whole package is new, so the incremental relay fee is paid over both.
		assert_eq!(fees(false).package_fee(parent, child), Amount::from_sat(11_000));
	}

	#[test]
	fn rbf_package_fee_rounds_up_to_whole_vbytes() {
		// 609 WU is 152.25 vB, which bitcoind counts as 153 vB.
		let parent = Weight::from_wu(801);
		let child = Weight::from_wu(609);
		let fees = |parent_in_mempool| MakeCpfpFees::Rbf {
			min_effective_fee_rate: FeeRate::from_sat_per_vb_u32(1),
			replaced_fee: Amount::from_sat(1_000),
			replaced_fee_rate: FeeRate::from_sat_per_vb_u32(1),
			incremental_relay_fee: FeeRate::from_sat_per_vb_u32(2),
			parent_in_mempool,
		};

		// 153 vB at 2 sat/vB, not 609 WU at 0.5 sat/WU.
		assert_eq!(fees(true).package_fee(parent, child), Amount::from_sat(1_306));
		// 201 vB and 153 vB, each rounded up on its own.
		assert_eq!(fees(false).package_fee(parent, child), Amount::from_sat(1_708));
	}
}
