
use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;

use ark::{VtxoId, VtxoPolicy, VtxoRequest};
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::BlockHeight;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPayHtlcsRequested {
	pub payment_hash: PaymentHash,
	pub expiry: BlockHeight,
}
impl_slog!(LightningPayHtlcsRequested, INFO, "requested HTLCs for lightning payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPaymentInitRequested {
	pub invoice_payment_hash: PaymentHash,
	pub htlc_vtxo_ids: Vec<VtxoId>,
}
impl_slog!(LightningPaymentInitRequested, TRACE, "requested lightning payment initiation");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPaymentInitiated {
	pub invoice_payment_hash: PaymentHash,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub fee: Amount,
	pub min_expiry: BlockHeight,
}
impl_slog!(LightningPaymentInitiated, INFO, "initiated lightning payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPayHtlcsRevocationRequested {
	pub invoice_payment_hash: PaymentHash,
	pub htlc_vtxo_ids: Vec<VtxoId>,
}
impl_slog!(LightningPayHtlcsRevocationRequested, TRACE, "requested htlc revocation");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPayHtlcsRevoked {
	pub invoice_payment_hash: PaymentHash,
	pub htlc_vtxo_ids: Vec<VtxoId>,
	pub new_vtxo_ids: Vec<VtxoId>,
}
impl_slog!(LightningPayHtlcsRevoked, INFO, "revoked HTLCs for lightning payment");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceivePrepareRequested {
	pub payment_hash: PaymentHash,
	pub user_pubkey: PublicKey,
	pub htlc_recv_expiry: BlockHeight,
}
impl_slog!(LightningReceivePrepareRequested, TRACE, "requested lightning receive HTLCs preparation");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceivePrepared {
	pub payment_hash: PaymentHash,
	pub htlc_vtxo_ids: Vec<VtxoId>,
	pub htlc_amount: Amount,
	pub fee: Amount,
}
impl_slog!(LightningReceivePrepared, INFO, "prepared HTLC VTXOs for lightning receive");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceiveCanceled {
	pub payment_hash: PaymentHash,
}
impl_slog!(LightningReceiveCanceled, INFO, "canceled lightning receive");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceiveClaimRequested {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	#[serde(with = "ark::encode::serde")]
	pub vtxo_policy: VtxoPolicy,
}
impl_slog!(LightningReceiveClaimRequested, TRACE, "requested lightning receive claim");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceiveClaimed {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub vtxo_request: VtxoRequest,
}
impl_slog!(LightningReceiveClaimed, INFO, "claimed lightning receive");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpayStarted {
	pub node_id: i64,
	pub created_index: u64,
	pub updated_index: u64,
}
impl_slog!(XpayStarted, INFO, "Start managing xpay");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpayStopped {
	pub node_id: i64,
	pub error: String,
}
impl_slog!(XpayStopped, ERROR, "Xpay exited with error");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpayRpcCalled {
	pub payment_hash: PaymentHash,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub payment_amount: Amount,
	pub invoice: String,
	pub max_delay: u32,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub max_routing_fee: Amount,
}
impl_slog!(XpayRpcCalled, DEBUG, "Calling xpay gRPC");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpayRpcReturned {
	pub payment_hash: PaymentHash,
	pub preimage: Option<Preimage>,
	pub error: Option<String>,
}
impl_slog!(XpayRpcReturned, DEBUG, "Xpay gRPC returned");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcSettled {
	pub payment_hash: PaymentHash,
	pub preimage: Preimage,
}
impl_slog!(HtlcSettled, DEBUG, "an HTLC was settled");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VtxoBucketPruned {
	pub threshold: BlockHeight,
	pub expiration_height: BlockHeight,
}
impl_slog!(VtxoBucketPruned, DEBUG, "Pruning vtxo bucket");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MustIssueVtxos {
	pub target_amount: Amount,
	pub current_count: usize,
	pub target_count: usize,
}
impl_slog!(MustIssueVtxos, DEBUG, "Must issue vtxos for target");
