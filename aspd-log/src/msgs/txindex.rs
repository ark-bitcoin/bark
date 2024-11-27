
use bitcoin::Txid;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxIndexUpdateFinished {
}
impl_slog!(TxIndexUpdateFinished, Trace, "finished updating all txindex txs");


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBroadcastError {
	pub txid: Txid,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_tx: Vec<u8>,
	pub error: String,
}
impl_slog!(TxBroadcastError, Error, "Error broadcasting one of our txs");

