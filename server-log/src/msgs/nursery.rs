
use bitcoin::Txid;
use bitcoin_ext::BlockHeight;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastingTx {
	pub txid: Txid,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_tx: Vec<u8>,
}
impl_slog!(BroadcastingTx, TRACE, "marked tx for broadcast");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBroadcastError {
	pub txid: Txid,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_tx: Vec<u8>,
	pub error: String,
}
impl_slog!(TxBroadcastError, ERROR, "Error broadcasting one of our txs");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NurseryTxConfirmed {
	pub txid: Txid,
	pub blockheight: BlockHeight,
}
impl_slog!(NurseryTxConfirmed, DEBUG, "nursery tx confirmed");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NurseryTxReorged {
	pub txid: Txid,
	pub previous_height: BlockHeight,
}
impl_slog!(NurseryTxReorged, WARN, "nursery tx was unconfirmed by a reorg");


/// Emitted on every new block until either the tx confirms or the
/// operator abandons it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NurseryTxMissedTarget {
	pub txid: Txid,
	pub confirm_target_height: BlockHeight,
	pub current_height: BlockHeight,
}
impl_slog!(NurseryTxMissedTarget, WARN,
	"nursery tx missed its confirmation target; operator intervention required"
);


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NurseryTxAbandoned {
	pub txid: Txid,
}
impl_slog!(NurseryTxAbandoned, WARN,
	"operator abandoned a nursery tx; it will no longer be followed up"
);
