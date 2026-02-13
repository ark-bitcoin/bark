
use ark::VtxoId;
use bitcoin::{Amount, OutPoint};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CosignedBoard {
	pub utxo: OutPoint,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}
impl_slog!(CosignedBoard, TRACE, "cosigned board tx for user");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredBoard {
	/// The utxo of the vtxo.
	pub vtxo: OutPoint,
	/// The on-chain utxo of the board.
	pub onchain_utxo: OutPoint,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}
impl_slog!(RegisteredBoard, TRACE, "registered board vtxo");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnconfirmedBoardRegisterAttempt {
	pub vtxo: VtxoId,
	pub confirmations: usize,
}
impl_slog!(UnconfirmedBoardRegisterAttempt, TRACE, "user attempted to register a board not sufficiently confirmed");
