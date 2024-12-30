
use bitcoin::{Amount, OutPoint};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignedOnboard {
	pub utxo: OutPoint,
	pub amount: Amount,
}
impl_slog!(CosignedOnboard, Trace, "cosigned onboard tx for user");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredOnboard {
	pub utxo: OutPoint,
	pub amount: Amount,
}
impl_slog!(RegisteredOnboard, Trace, "registered onboard vtxo");

