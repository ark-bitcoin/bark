
use ark::VtxoId;
use bitcoin::{Amount, OutPoint};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignedBoard {
	pub utxo: OutPoint,
	pub amount: Amount,
}
impl_slog!(CosignedBoard, Trace, "cosigned board tx for user");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredBoard {
	/// The utxo of the vtxo.
	pub vtxo: OutPoint,
	/// The on-chain utxo of the board.
	pub onchain_utxo: OutPoint,
	pub amount: Amount,
}
impl_slog!(RegisteredBoard, Trace, "registered board vtxo");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconfirmedBoardSpendAttempt {
	pub vtxo: VtxoId,
	pub confirmations: usize,
}
impl_slog!(UnconfirmedBoardSpendAttempt, Trace, "user attempted to spend board vtxo not deeply confirmed");
