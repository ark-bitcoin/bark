use std::{num::NonZeroUsize, time::Duration};

use bitcoin::{Amount, FeeRate};

use bitcoin_ext::BlockDelta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// Interval at which to react to on-chain exit activity: progressing exit
	/// chains and claiming VTXOs before a counterparty's timelock matures.
	/// This work races other parties, so it should run often.
	#[serde(with = "crate::utils::serde::duration")]
	pub reaction_interval: Duration,

	/// Interval at which to sweep VTXOs that only we can spend. Sweeps have
	/// no deadline, so this can be much longer than [Self::reaction_interval].
	#[serde(with = "crate::utils::serde::duration")]
	pub sweep_interval: Duration,

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
