
use bitcoin::{Amount, OutPoint, Txid};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignedOnboard {
	pub utxo: OutPoint,
	pub amount: Amount,
	pub reveal_txid: Txid,
}
impl_slog!(CosignedOnboard, Trace, "cosigned onboard tx for user");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredOnboard {
	/// The utxo of the vtxo.
	pub vtxo: OutPoint,
	/// The on-chain utxo of the onboard.
	pub onchain_utxo: OutPoint,
	pub amount: Amount,
}
impl_slog!(RegisteredOnboard, Trace, "registered onboard vtxo");

