
use bitcoin::Txid;
use bitcoin_ext::BlockHeight;
use serde::{Deserialize, Serialize};

use ark::VtxoId;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitedExitInMempool {
	pub vtxo: VtxoId,
	pub exit_tx: Txid,
}
impl_slog!(ForfeitedExitInMempool, WARN, "the exit tx of a forfeited vtxo was seen in the mempool");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitedExitConfirmed {
	pub vtxo: VtxoId,
	pub exit_tx: Txid,
	pub block_height: BlockHeight,
}
impl_slog!(ForfeitedExitConfirmed, WARN, "the exit tx of a forfeited vtxo has confirmed");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfirmed {
	pub connector_txid: Txid,
	pub vtxo: VtxoId,
	pub block_height: BlockHeight,
}
impl_slog!(ConnectorConfirmed, DEBUG, "the connector tx for a forfeit claim has confirmed");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForfeitBroadcasted {
	pub forfeit_txid: Txid,
	pub vtxo: VtxoId,
	pub cpfp_txid: Txid,
}
impl_slog!(ForfeitBroadcasted, DEBUG, "we broadcasted a forfeit tx");

