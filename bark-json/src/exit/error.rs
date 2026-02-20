use bitcoin::{Amount, FeeRate, Txid};
use thiserror::Error;

use ark::VtxoId;
use bitcoin_ext::BlockHeight;
#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

use crate::exit::states::ExitTxStatus;

#[derive(Clone, Debug, Error, PartialEq, Eq, Deserialize, Serialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitError {
	#[error("Transaction Retrieval Failure: Unable to retrieve ancestral data for TX {txid}: {error}")]
	AncestorRetrievalFailure {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		txid: Txid,
		error: String
	},

	#[error("Block Retrieval Failure: Unable to retrieve a block at height {height}: {error}")]
	BlockRetrievalFailure { height: BlockHeight, error: String },

	#[error("Claim Missing Inputs: No inputs given to claim")]
	ClaimMissingInputs,

	#[error("Claim Fee Exceeds Output: Cost to claim exits was {needed}, but the total output was {output}")]
	ClaimFeeExceedsOutput {
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		needed: Amount,
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		output: Amount,
	},

	#[error("Claim Missing Signable Clause: Couldn't find a signable clause for VTXO {vtxo}")]
	ClaimMissingSignableClause {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		vtxo: VtxoId,
	},

	#[error("Claim Signing Error: Unable to sign claim: {error}")]
	ClaimSigningError { error: String },

	#[error("Cyclic Exit Transactions Error: The exit transactions for VTXO {vtxo} are cyclic")]
	CyclicExitTransactions {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		vtxo: VtxoId
	},

	#[error("Database Store Failure: Unable to update exit VTXO {vtxo_id} in the database: {error}")]
	DatabaseVtxoStoreFailure {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		vtxo_id: VtxoId,
		error: String
	},

	#[error("Database Retrieval Failure: Unable to get child tx: {error}")]
	DatabaseChildRetrievalFailure { error: String },

	#[error("Dust Limit Error: The dust limit for a VTXO is {dust} but the balance is only {vtxo}")]
	DustLimit {
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		vtxo: Amount,
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		dust: Amount
	},

	#[error("Exit Package Broadcast Failure: Unable to broadcast exit transaction package {txid}: {error}")]
	ExitPackageBroadcastFailure {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		txid: Txid,
		error: String
	},

	#[error("Exit Package Finalize Failure: Unable to create exit transaction package: {error}")]
	ExitPackageFinalizeFailure { error: String },

	#[error("Exit Package Store Failure: Unable to store exit transaction package {txid}: {error}")]
	ExitPackageStoreFailure {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		txid: Txid,
		error: String
	},

	#[error("Insufficient Confirmed Funds: {needed} is needed but only {available} is available")]
	InsufficientConfirmedFunds {
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		needed: Amount,
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		available: Amount
	},

	#[error("Insufficient Fee Error: Your balance is {balance} but an estimated {total_fee} (fee rate of {fee_rate}) is required to exit the VTXO")]
	InsufficientFeeToStart {
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		balance: Amount,
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		total_fee: Amount,
		#[serde(rename = "fee_rate_sat_per_kvb", with = "crate::serde_utils::fee_rate_sat_per_kvb")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		fee_rate: FeeRate,
		#[deprecated(note = "use fee_rate_sat_per_kvb instead")]
		#[cfg_attr(feature = "utoipa", schema(value_type = u64))]
		fee_rate_kwu: u64,
	},

	#[error("Internal Error: An unexpected problem occurred, {error}")]
	InternalError { error: String },

	#[error("Invalid Exit Transaction Status: Exit tx {txid} has an invalid status ({status}): {error}")]
	InvalidExitTransactionStatus {
		#[cfg_attr(feature = "utoipa", schema(value_type = String))]
		txid: Txid,
		status: ExitTxStatus,
		error: String
	},

	#[error("Invalid LockTime ({tip}): {error}")]
	InvalidLocktime { tip: BlockHeight, error: String },

	#[error("Invalid Wallet State: {error}")]
	InvalidWalletState { error: String },

	#[error("Missing Anchor Output: Malformed exit tx {txid}")]
	MissingAnchorOutput { #[cfg_attr(feature = "utoipa", schema(value_type = String))] txid: Txid },

	#[error("Missing VTXO Transaction: Couldn't find exit tx {txid}")]
	MissingExitTransaction { #[cfg_attr(feature = "utoipa", schema(value_type = String))] txid: Txid },

	#[error("Movement Registration Failure: {error}")]
	MovementRegistrationFailure { error: String },

	#[error("Tip Retrieval Failure: Unable to retrieve the blockchain tip height: {error}")]
	TipRetrievalFailure { error: String },

	#[error("Transaction Retrieval Failure: Unable to check the status of TX {txid}: {error}")]
	TransactionRetrievalFailure { #[cfg_attr(feature = "utoipa", schema(value_type = String))] txid: Txid, error: String },

	#[error("VTXO Not Spendable Error: Attempted to claim a VTXO which is not in a spendable state: {vtxo}")]
	VtxoNotClaimable { #[cfg_attr(feature = "utoipa", schema(value_type = String))] vtxo: VtxoId },

	#[error("VTXO ScriptPubKey Invalid: {error}")]
	VtxoScriptPubKeyInvalid { error: String },
}

impl From<bark::exit::ExitError> for ExitError {
	fn from(v: bark::exit::ExitError) -> Self {
		match v {
			bark::exit::ExitError::AncestorRetrievalFailure { txid, error } => {
				ExitError::AncestorRetrievalFailure { txid, error }
			},
			bark::exit::ExitError::BlockRetrievalFailure { height, error } => {
				ExitError::BlockRetrievalFailure { height, error }
			},
			bark::exit::ExitError::ClaimMissingInputs => {
				ExitError::ClaimMissingInputs
			},
			bark::exit::ExitError::ClaimFeeExceedsOutput { needed, output } => {
				ExitError::ClaimFeeExceedsOutput { needed, output }
			},
			bark::exit::ExitError::ClaimMissingSignableClause { vtxo } => {
				ExitError::ClaimMissingSignableClause { vtxo }
			},
			bark::exit::ExitError::ClaimSigningError { error } => {
				ExitError::ClaimSigningError { error }
			},
			bark::exit::ExitError::CyclicExitTransactions { vtxo } => {
				ExitError::CyclicExitTransactions { vtxo }
			},
			bark::exit::ExitError::DatabaseVtxoStoreFailure { vtxo_id, error } => {
				ExitError::DatabaseVtxoStoreFailure { vtxo_id, error }
			},
			bark::exit::ExitError::DatabaseChildRetrievalFailure { error } => {
				ExitError::DatabaseChildRetrievalFailure { error }
			},
			bark::exit::ExitError::DustLimit { vtxo, dust } => {
				ExitError::DustLimit { vtxo, dust }
			},
			bark::exit::ExitError::ExitPackageBroadcastFailure { txid, error } => {
				ExitError::ExitPackageBroadcastFailure { txid, error }
			},
			bark::exit::ExitError::ExitPackageFinalizeFailure { error } => {
				ExitError::ExitPackageFinalizeFailure { error }
			},
			bark::exit::ExitError::ExitPackageStoreFailure { txid, error } => {
				ExitError::ExitPackageStoreFailure { txid, error }
			},
			bark::exit::ExitError::InsufficientConfirmedFunds { needed, available } => {
				ExitError::InsufficientConfirmedFunds { needed, available }
			},
			bark::exit::ExitError::InsufficientFeeToStart { balance, total_fee, fee_rate } => {
				let fee_rate_kwu = fee_rate.to_sat_per_kwu();
				ExitError::InsufficientFeeToStart { balance, total_fee, fee_rate, fee_rate_kwu }
			},
			bark::exit::ExitError::InternalError { error } => {
				ExitError::InternalError { error }
			},
			bark::exit::ExitError::InvalidExitTransactionStatus { txid, status, error } => {
				ExitError::InvalidExitTransactionStatus { txid, status: status.into(), error }
			},
			bark::exit::ExitError::InvalidLocktime { tip, error } => {
				ExitError::InvalidLocktime { tip, error }
			},
			bark::exit::ExitError::InvalidWalletState { error } => {
				ExitError::InvalidWalletState { error }
			},
			bark::exit::ExitError::MissingAnchorOutput { txid } => {
				ExitError::MissingAnchorOutput { txid }
			},
			bark::exit::ExitError::MissingExitTransaction { txid } => {
				ExitError::MissingExitTransaction { txid }
			},
			bark::exit::ExitError::MovementRegistrationFailure { error } => {
				ExitError::MovementRegistrationFailure { error }
			},
			bark::exit::ExitError::TipRetrievalFailure { error } => {
				ExitError::TipRetrievalFailure { error }
			},
			bark::exit::ExitError::TransactionRetrievalFailure { txid, error } => {
				ExitError::TransactionRetrievalFailure { txid, error }
			},
			bark::exit::ExitError::VtxoNotClaimable { vtxo } => {
				ExitError::VtxoNotClaimable { vtxo }
			},
			bark::exit::ExitError::VtxoScriptPubKeyInvalid { error } => {
				ExitError::VtxoScriptPubKeyInvalid { error }
			},
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	#[test]
	fn json_roundtrip() {
		let err = ExitError::InvalidWalletState { error: "none shall pass".into() };
		let json = serde_json::to_string(&err).unwrap();
		let err2 = serde_json::from_str::<ExitError>(&json).unwrap();
		assert_eq!(err, err2);
	}
}
