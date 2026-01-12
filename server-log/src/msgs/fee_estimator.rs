use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimateFallback {
	pub err: String,
}
impl_slog!(FeeEstimateFallback, WARN, "fee estimation failed, using fallback fee rates");
