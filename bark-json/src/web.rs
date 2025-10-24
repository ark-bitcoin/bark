use ark::lightning::{Bolt11Invoice, PaymentHash, Preimage};
use serde::{Deserialize, Serialize};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PeakAddressRequest {
	pub index: u32,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ArkAddressResponse {
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub address: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct VtxosQuery {
	/// Return all VTXOs regardless of their state (including spent ones)
	pub all: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct RefreshRequest {
	/// List of VTXO IDs to refresh
	pub vtxos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BoardRequest {
	/// Amount of on-chain funds to board (in satoshis)
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SendRequest {
	/// The destination can be an Ark address, a BOLT11-invoice, LNURL or a lightning address
	pub destination: String,
	/// The amount to send (in satoshis). Optional for bolt11 invoices
	pub amount_sat: Option<u64>,
	/// An optional comment, only supported when paying to lightning addresses
	pub comment: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SendResponse {
	/// Success message
	pub message: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SendOnchainRequest {
	/// The destination Bitcoin address
	pub destination: String,
	/// The amount to send (in satoshis)
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardVtxosRequest {
	/// Optional Bitcoin address to send to. If not provided, uses the onchain wallet's address
	pub address: Option<String>,
	/// List of VTXO IDs to offboard
	pub vtxos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardAllRequest {
	/// Optional Bitcoin address to send to. If not provided, uses the onchain wallet's address
	pub address: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningInvoiceRequest {
	/// The amount to create invoice for (in satoshis)
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningStatusRequest {
	/// Payment hash or invoice string
	pub filter: Option<String>,
	/// Filter by preimage
	pub preimage: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningStatusResponse {
	/// The payment hash of the invoice
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_hash: PaymentHash,
	/// The preimage that was used to pay the invoice
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub payment_preimage: Preimage,
	/// The invoice that was paid
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub invoice: Bolt11Invoice,
	/// The time the preimage was revealed
	pub preimage_revealed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningPayRequest {
	/// The invoice, offer, or lightning address to pay
	pub destination: String,
	/// The amount to send (in satoshis). Optional for bolt11 invoices with amount
	pub amount_sat: Option<u64>,
	/// An optional comment, only supported when paying to lightning addresses
	pub comment: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningPayResponse {
	/// Success message
	pub message: String,
	/// The payment preimage (for successful payments)
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub preimage: Option<Preimage>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OnchainSendRequest {
	/// The destination Bitcoin address
	pub destination: String,
	/// The amount to send (in satoshis)
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OnchainSendManyRequest {
	/// List of destinations in format "address:amount"
	pub destinations: Vec<String>,
	/// Sends the transaction immediately instead of waiting
	pub immediate: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OnchainDrainRequest {
	/// The destination Bitcoin address
	pub destination: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitStatusRequest {
	/// The VTXO to check the exit status of
	pub vtxo: String,
	/// Whether to include the detailed history of the exit process
	pub history: Option<bool>,
	/// Whether to include the exit transactions and their CPFP children
	pub transactions: Option<bool>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitListRequest {
	/// Whether to include the detailed history of the exit process
	pub history: Option<bool>,
	/// Whether to include the exit transactions and their CPFP children
	pub transactions: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitStartRequest {
	/// The ID of VTXOs to unilaterally exit
	pub vtxos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitStartResponse {
	pub message: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitProgressRequest {
	/// Wait until the exit is completed
	pub wait: Option<bool>,
	/// Sets the desired fee-rate in sats/kvB to use broadcasting exit transactions
	pub fee_rate: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimRequest {
	/// The destination Bitcoin address
	pub destination: String,
	/// The ID of an exited VTXO to be claimed
	pub vtxos: Option<Vec<String>>,
	/// Claim all exited VTXOs
	pub all: Option<bool>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimResponse {
	pub message: String,
}