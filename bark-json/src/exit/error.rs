use bitcoin::{Amount, FeeRate, Txid};
use bitcoin::address::FromScriptError;
use thiserror::Error;

use ark::VtxoId;
use bitcoin_ext::BlockHeight;

use crate::exit::states::ExitTxStatus;

#[derive(Clone, Debug, Error, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ExitError {
	#[error("Block Retrieval Failure: Unable to retrieve a block at height {height}: {error}")]
	BlockRetrievalFailure { height: BlockHeight, error: String },

	#[error("Cyclic Exit Transactions Error: The exit transactions for VTXO {0} are cyclic")]
	CyclicExitTransactions(VtxoId),

	#[error("Database Store Failure: Unable to update exit VTXO {vtxo_id} in the database: {error}")]
	DatabaseVtxoStoreFailure { vtxo_id: VtxoId, error: String },

	#[error("Database Retrieval Failure: Unable to get child tx: {0}")]
	DatabaseChildRetrievalFailure(String),

	#[error("Dust Limit Error: The dust limit for a VTXO is {dust} but the balance is only {vtxo}")]
	DustLimit { vtxo: Amount, dust: Amount },

	#[error("Exit Package Finalize Failure: Unable to create exit transaction package: {0}")]
	ExitPackageFinalizeFailure(String),

	#[error("Insufficient Confirmed Funds: {needed} is needed but only {available} is available")]
	InsufficientConfirmedFunds { needed: Amount, available: Amount },

	#[error("Insufficient Fee Error: Your balance is {balance} but an estimated {total_fee} (fee rate of {fee_rate}) is required to exit the VTXO")]
	InsufficientFeeToStart { balance: Amount, total_fee: Amount, fee_rate: FeeRate },

	#[error("Internal Error: An unexpected problem occurred, {0}")]
	InternalError(String),

	#[error("Invalid Exit Transaction Status: Exit tx {txid} has an invalid status ({status}): {error}")]
	InvalidExitTransactionStatus { txid: Txid, status: ExitTxStatus, error: String },

	#[error("Invalid Wallet State: {0}")]
	InvalidWalletState(String),

	#[error("Missing Anchor Output: Malformed exit tx {0}")]
	MissingAnchorOutput(Txid),

	#[error("Missing VTXO Transaction: Couldn't find exit tx {0}")]
	MissingExitTransaction(Txid),

	#[error("Movement Registration Failure: {0}")]
	MovementRegistrationFailure(String),

	#[error("Tip Retrieval Failure: Unable to retrieve the blockchain tip height: {0}")]
	TipRetrievalFailure(String),

	#[error("Transaction Retrieval Failure: Unable to check the status of TX {txid}: {error}")]
	TransactionRetrievalFailure { txid: Txid, error: String },

	#[error("VTXO ScriptPubKey Invalid: {0}")]
	VtxoScriptPubKeyInvalid(String),
}

impl From<FromScriptError> for ExitError {
	fn from(e: FromScriptError) -> Self {
		ExitError::VtxoScriptPubKeyInvalid(e.to_string())
	}
}
