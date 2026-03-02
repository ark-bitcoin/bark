use std::{num::NonZeroUsize, time::Duration};

use bitcoin::{Amount, FeeRate};

use bitcoin_ext::BlockDelta;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Interval at which to process VTXOs.
	#[serde(with = "crate::utils::serde::duration")]
	pub process_interval: Duration,

	/// This grace period allows users who are performing an exit to complete
	/// their on-chain transaction before the server interferes by attempting
	/// to progress the VTXO.
	pub progress_grace_period: BlockDelta,

	/// Maximum number of VTXOs to process in a single claim transaction.
	pub claim_chunksize: NonZeroUsize,

	/// Minimum fee bump required for RBF in sat/kvb.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub incremental_relay_fee: FeeRate,

	/// Minimum confirmed funds in sats required to create a CPFP transaction.
	#[serde(with = "crate::utils::serde::string")]
	pub min_cpfp_amount: Amount,
}
