use bitcoin::FeeRate;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateFallback {
	pub err: String,
}
impl_slog!(FeeEstimateFallback, WARN, "fee estimation failed, using fallback fee rates");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRatesUpdated {
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub new_fast: FeeRate,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub old_fast: FeeRate,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub new_regular: FeeRate,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub old_regular: FeeRate,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub new_slow: FeeRate,
	#[serde(with = "crate::serde_utils::fee_rate")]
	pub old_slow: FeeRate,
}
impl_slog!(FeeRatesUpdated, DEBUG, "fee rates updated");
