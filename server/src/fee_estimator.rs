//! Onchain fee rate estimation and caching.
//!
//! This module provides a background process that periodically fetches fee rate
//! estimates from bitcoind and caches them for use throughout the server.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use bitcoin::FeeRate;
use tokio::time::Instant;
use tracing::info;

use bitcoin_ext::FeeRateExt;
use bitcoin_ext::rpc;
use bitcoind_async_client::Client as BitcoindClient;

use crate::bitcoind as bcd;
use crate::system::RuntimeManager;
use crate::telemetry;

const FEE_RATE_TARGET_CONF_FAST: u16 = 1;
const FEE_RATE_TARGET_CONF_REGULAR: u16 = 3;
const FEE_RATE_TARGET_CONF_SLOW: u16 = 6;

/// Cached fee rates for different confirmation targets.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OnchainFeeRates {
	/// Fee rate for fast transactions (1-block confirmation target).
	pub fast: FeeRate,
	/// Fee rate for regular transactions (3-block confirmation target).
	pub regular: FeeRate,
	/// Fee rate for slow transactions (6-block confirmation target).
	pub slow: FeeRate,
}

impl OnchainFeeRates {
	/// Apply a max fee rate to all rates
	pub fn max(&mut self, max_fee_rate: FeeRate) {
		*self = OnchainFeeRates {
			fast: self.fast.max(max_fee_rate),
			regular: self.regular.max(max_fee_rate),
			slow: self.slow.max(max_fee_rate),
		};
	}
}

/// Configuration for the fee estimator process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	/// Interval between fee rate updates.
	#[serde(with = "crate::utils::serde::duration")]
	pub update_interval: Duration,
	/// How long to maintain the fee rate history for; this impacts how long certain fee rates are
	/// valid.
	#[serde(with = "crate::utils::serde::duration")]
	pub history_duration: Duration,
	/// Fallback fee rate for fast transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_fast: FeeRate,
	/// Fallback fee rate for regular transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_regular: FeeRate,
	/// Fallback fee rate for slow transactions when estimation fails.
	#[serde(with = "crate::utils::serde::fee_rate")]
	pub fallback_fee_rate_slow: FeeRate,
	/// Optional ceiling applied to every fetched fee rate.
	///
	/// If the backend returns a rate above this value (e.g. due to a bad
	/// mempool spike), it is clamped down to this maximum instead of being
	/// used verbatim.  Leave unset to impose no ceiling.
	#[serde(default, with = "crate::utils::serde::fee_rate::opt")]
	pub max_fee_rate: Option<FeeRate>,
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
pub struct FeeEstimator {
	fee_rates: parking_lot::RwLock<VecDeque<(OnchainFeeRates, Instant)>>,
	history_duration: Duration,
	max_fee_rate: Option<FeeRate>,
}

impl FeeEstimator {
	fn new(
		initial: OnchainFeeRates,
		history_duration: Duration,
		max_fee_rate: Option<FeeRate>,
	) -> Self {
		Self {
			fee_rates: parking_lot::RwLock::new([(initial, Instant::now())].into()),
			history_duration, max_fee_rate,
		}
	}

	/// Returns the fast fee rate (1-block confirmation target).
	pub fn fast(&self) -> FeeRate {
		self.get_current_rates().fast
	}

	/// Returns the regular fee rate (3-block confirmation target).
	pub fn regular(&self) -> FeeRate {
		self.get_current_rates().regular
	}

	/// Returns the slow fee rate (6-block confirmation target).
	pub fn slow(&self) -> FeeRate {
		self.get_current_rates().slow
	}

	/// Checks if the given fee rate is considered a historically retrieved fast fee rate during the
	/// given duration.
	///
	/// Note: If the duration is longer than the fee estimator's configured history, then the result
	/// will be limited by that. Historical data is not persisted, so it will be cleared by a
	/// restart.
	pub fn is_historical_fast_rate(&self, fee_rate: FeeRate, duration: Duration) -> bool {
		self.is_historical_rate(fee_rate, duration, |rates| rates.fast)
	}

	/// Checks if the given fee rate is considered a historically retrieved regular fee rate during
	/// the given duration.
	///
	/// Note: If the duration is longer than the fee estimator's configured history, then the result
	/// will be limited by that. Historical data is not persisted, so it will be cleared by a
	/// restart.
	pub fn is_historical_regular_rate(&self, fee_rate: FeeRate, duration: Duration) -> bool {
		self.is_historical_rate(fee_rate, duration, |rates| rates.regular)
	}

	/// Checks if the given fee rate is considered a historically retrieved slow fee rate during the
	/// given duration.
	///
	/// Note: If the duration is longer than the fee estimator's configured history, then the result
	/// will be limited by that. Historical data is not persisted, so it will be cleared by a
	/// restart.
	pub fn is_historical_slow_rate(&self, fee_rate: FeeRate, duration: Duration) -> bool {
		self.is_historical_rate(fee_rate, duration, |rates| rates.slow)
	}

	fn get_current_rates(&self) -> OnchainFeeRates {
		self.fee_rates.read().front().expect("FeeEstimator is not initialized yet").0
	}

	fn is_historical_rate<F>(&self, fee_rate: FeeRate, duration: Duration, getter: F) -> bool
	where
		F: Fn(&OnchainFeeRates) -> FeeRate,
	{
		let now = Instant::now();
		let fee_rates = self.fee_rates.read();
		for (rates, timestamp) in fee_rates.iter() {
			if now - *timestamp > duration {
				break;
			}
			if getter(rates) >= fee_rate {
				return true;
			}
		}
		false
	}

	fn update(&self, mut rates: OnchainFeeRates) {
		if let Some(max) = self.max_fee_rate {
			rates.max(max);
		}

		let mut deque = self.fee_rates.write();
		let now = Instant::now();
		while deque.back().is_some_and(|(_, timestamp)| now - *timestamp >= self.history_duration) {
			deque.pop_back();
		}
		deque.push_front((rates, Instant::now()));
	}
}

struct Process {
	config: Config,
	bitcoind: BitcoindClient,
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
					self.update_fee_rates().await;
				}
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting FeeEstimator loop...");
					break;
				}
			}
		}

		info!("FeeEstimator terminated gracefully.");
	}

	async fn update_fee_rates(&self) {
		let (rates, using_fallback) = match self.fetch_fee_rates().await {
			Ok(rates) => (rates, false),
			Err(e) => {
				slog!(FeeEstimateFallback, err: e.to_string());
				let rates = self.config.fallback_fee_rates();
				self.fee_estimator.update(rates);
				(self.config.fallback_fee_rates(), true)
			}
		};

		// Convert sat/kwu to sat/vb: 1 vbyte = 4 weight units, so sat/vb = sat/kwu / 250
		let to_sat_per_vb = |rate: FeeRate| rate.to_sat_per_kwu() as f64 / 250.0;
		telemetry::set_fee_estimator_metrics(
			to_sat_per_vb(rates.fast),
			to_sat_per_vb(rates.regular),
			to_sat_per_vb(rates.slow),
			using_fallback,
		);

		self.fee_estimator.update(rates);
	}

	async fn fetch_fee_rates(&self) -> anyhow::Result<OnchainFeeRates> {
		let get_fee_rate = async |target: u16| -> anyhow::Result<FeeRate> {
			let fee: rpc::json::EstimateSmartFeeResult = self.bitcoind.call_raw(
				"estimatesmartfee",
				&[
					target.into(),
					bcd::json_arg(rpc::json::EstimateMode::Conservative)?,
				],
			).await?;
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
			fast: get_fee_rate(FEE_RATE_TARGET_CONF_FAST).await?,
			regular: get_fee_rate(FEE_RATE_TARGET_CONF_REGULAR).await?,
			slow: get_fee_rate(FEE_RATE_TARGET_CONF_SLOW).await?,
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
	bitcoind: BitcoindClient,
) -> Arc<FeeEstimator> {
	// Initialize with fallback rates
	let fee_estimator = Arc::new(FeeEstimator::new(
		config.fallback_fee_rates(), config.history_duration, config.max_fee_rate,
	));

	let process = Process {
		config,
		bitcoind,
		fee_estimator: fee_estimator.clone(),
	};

	tokio::spawn(process.run(rtmgr));

	fee_estimator
}
