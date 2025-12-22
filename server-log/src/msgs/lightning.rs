
use bitcoin::Amount;
use bitcoin::secp256k1::PublicKey;

use ark::{VtxoId, VtxoPolicy, VtxoRequest};
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::BlockHeight;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningPayHtlcsRequested {
	pub invoice_payment_hash: PaymentHash,
	pub amount: Amount,
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
	pub amount: Amount,
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
	pub vtxo_request: VtxoRequest,
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
}
impl_slog!(LightningReceivePrepared, INFO, "prepared HTLC VTXOs for lightning receive");

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

