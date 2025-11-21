use ark::lightning::{Bolt11Invoice, PaymentHash, Preimage};
use serde::{Deserialize, Serialize};
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TipResponse {
	pub tip_height: u32,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PeakAddressRequest {
	pub index: u32,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ConnectedResponse {
	/// Whether the wallet is currently connected to its Ark server
	pub connected: bool,
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
pub struct ExitClaimAllRequest {
	/// The destination Bitcoin address
	pub destination: String,
	/// Sets the desired fee-rate in sats/kvB to use broadcasting exit transactions
	pub fee_rate: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimVtxosRequest {
	/// The destination Bitcoin address
	pub destination: String,
	/// The ID of an exited VTXO to be claimed
	pub vtxos: Vec<String>,
	/// Sets the desired fee-rate in sats/kvB to use broadcasting exit transactions
	pub fee_rate: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ExitClaimResponse {
	pub message: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PendingRoundInfo {
	/// Unique identifier for the round
	pub id: u32,
	/// Discriminant of the round state
	pub kind: String,
	/// Round sequence number, if known
	pub round_seq: Option<u64>,
	/// Attempt sequence number within the round, if known
	pub attempt_seq: Option<usize>,
	/// The round transaction id, if already assigned
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub round_txid: Option<ark::rounds::RoundId>,
}

impl From<bark::persist::StoredRoundState> for PendingRoundInfo {
	fn from(state: bark::persist::StoredRoundState) -> Self {
		match state.state.flow() {
			bark::round::RoundFlowState::WaitingToStart => {
				PendingRoundInfo {
					id: state.id.0,
					kind: "WaitingToStart".to_string(),
					round_seq: None,
					attempt_seq: None,
					round_txid: None,
				}
			},
			bark::round::RoundFlowState::Ongoing { round_seq, attempt_seq, state: attempt_state } => {
				// Map attempt state kind to the old kind strings
				let kind = match attempt_state {
					bark::round::AttemptState::AwaitingAttempt => "AttemptStarted",
					bark::round::AttemptState::AwaitingUnsignedVtxoTree { .. } => "PaymentSubmitted",
					bark::round::AttemptState::AwaitingRoundProposal { .. } => "VtxoTreeSigned",
					bark::round::AttemptState::AwaitingFinishedRound { .. } => "ForfeitSigned",
				};
				// Get round_txid from unconfirmed_rounds if available
				let round_txid = state.state.unconfirmed_rounds().first()
					.map(|r| r.funding_txid())
					.map(|txid| ark::rounds::RoundId::from(txid));

				PendingRoundInfo {
					id: state.id.0,
					kind: kind.to_string(),
					round_seq: Some(round_seq.inner() as u64),
					attempt_seq: Some(*attempt_seq),
					round_txid: round_txid,
				}
			},
			bark::round::RoundFlowState::Success => {
				// If we have unconfirmed rounds, it's pending confirmation
				// Otherwise it's a completed success state
				if !state.state.unconfirmed_rounds().is_empty() {
					let round_txid = state.state.unconfirmed_rounds().first()
						.map(|r| r.funding_txid())
						.map(|txid| ark::rounds::RoundId::from(txid));

					PendingRoundInfo {
						id: state.id.0,
						kind: "PendingConfirmation".to_string(),
						round_seq: None,
						attempt_seq: None,
						round_txid: round_txid,
					}
				} else {
					PendingRoundInfo {
						id: state.id.0,
						kind: "RoundConfirmed".to_string(),
						round_seq: None,
						attempt_seq: None,
						round_txid: None,
					}
				}
			},
			bark::round::RoundFlowState::Failed { .. } => {
				let round_txid = state.state.unconfirmed_rounds().first()
					.map(|r| r.funding_txid())
					.map(|txid| ark::rounds::RoundId::from(txid));

				PendingRoundInfo {
					id: state.id.0,
					kind: "RoundFailed".to_string(),
					round_seq: None,
					attempt_seq: None,
					round_txid: round_txid,
				}
			},
			bark::round::RoundFlowState::Canceled => {
				PendingRoundInfo {
					id: state.id.0,
					kind: "RoundCanceled".to_string(),
					round_seq: None,
					attempt_seq: None,
					round_txid: None,
				}
			},
		}
	}
}
