
use bitcoin::Txid;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIndexUpdateFinished {
}
impl_slog!(TxIndexUpdateFinished, TRACE, "finished updating all txindex txs");


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
pub struct DifferentDuplicate {
	pub txid: Txid,
	pub raw_tx_original: Vec<u8>,
	pub raw_tx_duplicate: Vec<u8>,
}
impl_slog!(DifferentDuplicate, ERROR,
	"second tx sent for broadcast is different from the original"
);
