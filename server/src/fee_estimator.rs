//! Onchain fee rate estimation and caching.
//!
//! This module provides a background process that periodically fetches fee rate
//! estimates from bitcoind and caches them for use throughout the server.

use std::sync::Arc;
use std::time::Duration;

use bitcoin::FeeRate;
use bitcoin_ext::FeeRateExt;
use bitcoin_ext::rpc::{self, BitcoinRpcClient, RpcApi};
use tracing::info;

use crate::system::RuntimeManager;

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

/// Cached fee rates for different confirmation targets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OnchainFeeRates {
	/// Fee rate for fast transactions (1-block confirmation target).
	pub fast: FeeRate,
	/// Fee rate for regular transactions (3-block confirmation target).
	pub regular: FeeRate,
	/// Fee rate for slow transactions (6-block confirmation target).
	pub slow: FeeRate,
}

/// Configuration for the fee estimator process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Interval between fee rate updates.
	#[serde(with = "crate::utils::serde::duration")]
	pub update_interval: Duration,
	/// Fallback fee rate for fast transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_fast: FeeRate,
	/// Fallback fee rate for regular transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_regular: FeeRate,
	/// Fallback fee rate for slow transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_slow: FeeRate,
}

impl Config {
	/// Returns the configured fallback fee rates.
	pub fn fallback_fee_rates(&self) -> OnchainFeeRates {
		OnchainFeeRates {
			fast: self.fallback_fee_rate_fast,
			regular: self.fallback_fee_rate_regular,
			slow: self.fallback_fee_rate_slow,
		}
	}
}

/// Provides access to cached fee rate estimates.
///
/// The fee rates are updated periodically by a background process.
/// Use [FeeEstimator::fee_rates] to get the current cached rates.
pub struct FeeEstimator {
	fee_rates: parking_lot::RwLock<OnchainFeeRates>,
}

impl FeeEstimator {
	fn new(initial: OnchainFeeRates) -> Self {
		Self {
			fee_rates: parking_lot::RwLock::new(initial),
		}
	}

	/// Returns the fast fee rate (1-block confirmation target).
	pub fn fast(&self) -> FeeRate {
		self.fee_rates.read().fast
	}

	/// Returns the regular fee rate (3-block confirmation target).
	pub fn regular(&self) -> FeeRate {
		self.fee_rates.read().regular
	}

	/// Returns the slow fee rate (6-block confirmation target).
	pub fn slow(&self) -> FeeRate {
		self.fee_rates.read().slow
	}

	fn update(&self, rates: OnchainFeeRates) {
		*self.fee_rates.write() = rates;
	}
}

struct Process {
	config: Config,
	bitcoind: BitcoinRpcClient,
	fee_estimator: Arc<FeeEstimator>,
}

impl Process {
	async fn run(self, rtmgr: RuntimeManager) {
		let _worker = rtmgr.spawn_critical("FeeEstimator");
		info!("Starting FeeEstimator...");

		let mut interval = tokio::time::interval(self.config.update_interval);
		interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

		loop {
			tokio::select! {
				_ = interval.tick() => {
					self.update_fee_rates();
				}
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting FeeEstimator loop...");
					break;
				}
			}
		}

		info!("FeeEstimator terminated gracefully.");
	}

	fn update_fee_rates(&self) {
		match self.fetch_fee_rates() {
			Ok(rates) => self.fee_estimator.update(rates),
			Err(e) => {
				slog!(FeeEstimateFallback, err: e.to_string());
				let rates = self.config.fallback_fee_rates();
				self.fee_estimator.update(rates);
			}
		}
	}

	fn fetch_fee_rates(&self) -> anyhow::Result<OnchainFeeRates> {
		let get_fee_rate = |target: u16| -> anyhow::Result<FeeRate> {
			let fee = self.bitcoind.estimate_smart_fee(
				target, Some(rpc::json::EstimateMode::Conservative),
			)?;
			if let Some(fee_rate) = fee.fee_rate {
				Ok(FeeRate::from_amount_per_kvb_ceil(fee_rate))
			} else {
				Err(anyhow!(
					"No rate returned from estimate_smart_fee for a {} confirmation target",
					target
				))
			}
		};

		Ok(OnchainFeeRates {
			fast: get_fee_rate(FEE_RATE_TARGET_CONF_FAST)?,
			regular: get_fee_rate(FEE_RATE_TARGET_CONF_REGULAR)?,
			slow: get_fee_rate(FEE_RATE_TARGET_CONF_SLOW)?,
		})
	}
}

/// Starts the fee estimator background process.
///
/// Returns a handle to the [FeeEstimator] that can be used to query the
/// current cached fee rates.
pub fn start(
	rtmgr: RuntimeManager,
	config: Config,
	bitcoind: BitcoinRpcClient,
) -> Arc<FeeEstimator> {
	// Initialize with fallback rates
	let fee_estimator = Arc::new(FeeEstimator::new(config.fallback_fee_rates()));

	let process = Process {
		config,
		bitcoind,
		fee_estimator: fee_estimator.clone(),
	};

	tokio::spawn(process.run(rtmgr));

	fee_estimator
}
