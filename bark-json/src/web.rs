
use bitcoin::{Amount, FeeRate, Txid};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::secp256k1::PublicKey;
use serde::{Deserialize, Serialize};

use ark::VtxoId;
use ark::offboard::OffboardRequest;
use ark::tree::signed::UnlockHash;
use ark::vtxo::VtxoPolicyKind;

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::cli::RoundStatus;


/// Query parameters for fee estimates that only require an amount.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct FeeEstimateQuery {
	/// The amount in satoshis to estimate fees for
	pub amount_sat: u64,
}

/// Query parameters for send-onchain fee estimates.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SendOnchainFeeEstimateQuery {
	/// The amount in satoshis to send
	pub amount_sat: u64,
	/// The destination Bitcoin address
	pub address: String,
}

/// Query parameters for offboard-all fee estimates.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardAllFeeEstimateQuery {
	/// The destination Bitcoin address
	pub address: String,
}

/// A fee estimate for an Ark wallet operation.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct FeeEstimateResponse {
	/// The total amount including fees (in satoshis)
	#[serde(rename = "gross_amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub gross_amount: Amount,
	/// The fee portion (in satoshis)
	#[serde(rename = "fee_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub fee: Amount,
	/// The amount excluding fees (in satoshis). For sends, this is the amount
	/// the recipient receives. For receives, this is the amount the user gets.
	#[serde(rename = "net_amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub net_amount: Amount,
	/// The VTXOs that would be spent for this operation
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub vtxos_spent: Vec<VtxoId>,
}

impl From<bark::FeeEstimate> for FeeEstimateResponse {
	fn from(estimate: bark::FeeEstimate) -> Self {
		FeeEstimateResponse {
			gross_amount: estimate.gross_amount,
			fee: estimate.fee,
			net_amount: estimate.net_amount,
			vtxos_spent: estimate.vtxos_spent,
		}
	}
}

/// Mempool fee rates for on-chain transactions.
#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OnchainFeeRatesResponse {
	/// Fee rate targeting ~1 block confirmation (sat/vB)
	pub fast_sat_per_vb: u64,
	/// Fee rate targeting ~3 block confirmation (sat/vB)
	pub regular_sat_per_vb: u64,
	/// Fee rate targeting ~6 block confirmation (sat/vB)
	pub slow_sat_per_vb: u64,
}


#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct TipResponse {
	pub tip_height: u32,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct CreateWalletRequest {
	/// The Ark server to use for the wallet
	pub ark_server: String,
	/// The chain source to use for the wallet
	pub chain_source: ChainSourceConfig,
	/// The optional mnemonic to use for the wallet
	pub mnemonic: Option<String>,
	/// The network to use for the wallet
	pub network: BarkNetwork,
	/// An optional birthday height to start syncing the wallet from
	pub birthday_height: Option<u32>,
}

/// Networks bark can be used on
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum BarkNetwork {
	/// Bitcoin's mainnet
	Mainnet,
	/// The official Bitcoin Core signet
	Signet,
	/// Mutinynet
	Mutinynet,
	/// Any regtest network
	Regtest,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum ChainSourceConfig {
	/// Use a bitcoind RPC server
	Bitcoind {
		bitcoind: String,
		bitcoind_auth: BitcoindAuth,
	},
	/// Use an Esplora HTTP server
	Esplora {
		url: String,
	},
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum BitcoindAuth {
	/// Use a cookie file for authentication
	Cookie {
		cookie: String,
	},
	/// Use a username and password for authentication
	UserPass {
		user: String,
		pass: String,
	},
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct CreateWalletResponse {
	pub fingerprint: String,
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
	/// List of VTXO IDs to refresh. The sum of the VTXOs being refreshed must be
	/// >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). Keep in mind that fees set out in
	/// [RefreshFees](crate::cli::RefreshFees) will be deducted from the newly created VTXO, this
	/// value must also be >= [P2TR_DUST](bitcoin_ext::P2TR_DUST).
	pub vtxos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct BoardRequest {
	/// An amount of onchain funds to board (in satoshis). For a board operation to be successful,
	/// this value, with any server-configured [BoardFees](crate::cli::BoardFees) deducted, must be
	/// >= [P2TR_DUST](bitcoin_ext::P2TR_DUST).
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SendRequest {
	/// The destination can be an Ark address, a BOLT11-invoice, LNURL or a lightning address
	pub destination: String,
	/// The amount to send (in satoshis). Optional for bolt11 invoices. Depending on the
	/// `destination`, the wallet must contain this amount plus any fees configured by the server in
	/// [FeeSchedule](crate::cli::FeeSchedule).
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
	/// The amount (in satoshis) to be received by `destination` onchain. Must be
	/// >= [P2TR_DUST](bitcoin_ext::P2TR_DUST). Server-configured fees laid out in
	/// [OffboardFees](crate::cli::OffboardFees) will be added on top of this amount.
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardVtxosRequest {
	/// Optional Bitcoin address to send to. If not provided, uses the onchain wallet's address
	pub address: Option<String>,
	/// List of VTXO IDs to offboard. The sum of the VTXOs being refreshed must be
	/// >= [P2TR_DUST](bitcoin_ext::P2TR_DUST) after the server-configured
	/// [OffboardFees](crate::cli::OffboardFees) are deducted.
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
pub struct ImportVtxoRequest {
	/// Hex-encoded VTXOs to import
	pub vtxos: Vec<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningInvoiceRequest {
	/// The amount to create invoice for (in satoshis). This is the amount the payee will pay but
	/// the final amount received by the client will have any server-configured
	/// [LightningReceiveFees](crate::cli::LightningReceiveFees) deducted.
	pub amount_sat: u64,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningPayRequest {
	/// The invoice, offer, or lightning address to pay
	pub destination: String,
	/// The amount to send (in satoshis). Optional for bolt11 invoices with amount. This must be
	/// higher than the minimum fee laid out in server-configured
	/// [LightningSendFees](crate::cli::LightningSendFees). The wallet must also contain enough
	/// funds to cover the amount plus any fees.
	pub amount_sat: Option<u64>,
	/// An optional comment, only supported when paying to lightning addresses
	pub comment: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LightningPayResponse {
	/// Success message
	pub message: String,
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
pub struct VtxoRequestInfo {
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub amount: Amount,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub policy_type: VtxoPolicyKind,
	#[cfg_attr(feature = "utoipa", schema(value_type = String))]
	pub user_pubkey: PublicKey,
}

impl<'a> From<&'a ark::VtxoRequest> for VtxoRequestInfo {
	fn from(v: &'a ark::VtxoRequest) -> Self {
		Self {
			amount: v.amount,
			policy_type: v.policy.policy_type(),
			user_pubkey: v.policy.user_pubkey(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct OffboardRequestInfo {
	/// hexadecimal representation of the output script
	pub script_pubkey_hex: String,
	/// opcode representation of the output script
	pub script_pubkey_asm: String,
	/// The target amount in sats.
	#[serde(rename = "net_amount_sat", with = "bitcoin::amount::serde::as_sat")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub net_amount: Amount,
	/// Determines whether fees should be added onto the given amount or deducted from it.
	pub deduct_fees_from_gross_amount: bool,
	/// What fee rate was used when calculating the fee for the offboard.
	#[serde(rename = "fee_rate_kwu")]
	#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
	pub fee_rate: FeeRate,
}

impl<'a> From<&'a OffboardRequest> for OffboardRequestInfo {
	fn from(v: &'a OffboardRequest) -> Self {
		Self {
			script_pubkey_hex: v.script_pubkey.to_hex_string(),
			script_pubkey_asm: v.script_pubkey.to_asm_string(),
			net_amount: v.net_amount,
			deduct_fees_from_gross_amount: v.deduct_fees_from_gross_amount,
			fee_rate: v.fee_rate,
		}
	}
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct RoundParticipationInfo {
	#[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
	pub inputs: Vec<VtxoId>,
	pub outputs: Vec<VtxoRequestInfo>,
}

impl<'a> From<&'a bark::round::RoundParticipation> for RoundParticipationInfo {
	fn from(v: &'a bark::round::RoundParticipation) -> Self {
		Self {
			inputs: v.inputs.iter().map(|v| v.id()).collect(),
			outputs: v.outputs.iter().map(Into::into).collect(),
		}
	}
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PendingRoundInfo {
	/// Unique identifier for the round
	pub id: u32,
	/// the current status of the round
	pub status: RoundStatus,
	/// the round participation details
	pub participation: RoundParticipationInfo,
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub unlock_hash: Option<UnlockHash>,
	/// The round transaction id, if already assigned
	#[cfg_attr(feature = "utoipa", schema(value_type = String, nullable = true))]
	pub funding_txid: Option<Txid>,
	pub funding_tx_hex: Option<String>,
}

impl PendingRoundInfo {
	pub fn new<'a>(
		state: &'a bark::persist::models::StoredRoundState,
		sync_result: anyhow::Result<bark::round::RoundStatus>,
	) -> Self {
		let funding_tx = state.state().funding_tx();
		Self {
			id: state.id().0,
			status: match sync_result {
				Ok(status) => status.into(),
				Err(e) => RoundStatus::SyncError {
					error: format!("{:#}", e),
				},
			},
			participation: state.state().participation().into(),
			unlock_hash: state.state().unlock_hash(),
			funding_txid: funding_tx.map(|t| t.compute_txid()),
			funding_tx_hex: funding_tx.map(|t| serialize_hex(t)),
		}
	}
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletExistsResponse {
	pub fingerprint: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletDeleteRequest {
	pub dangerous: bool,
	pub fingerprint: String,
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WalletDeleteResponse {
	pub deleted: bool,
	pub message: String,
}

