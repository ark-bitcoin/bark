use bitcoin::{Amount, FeeRate, Txid};
use bitcoin::address::FromScriptError;
use thiserror::Error;

use ark::VtxoId;
use bitcoin_ext::BlockHeight;

use crate::exit::models::states::ExitTxStatus;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ExitError {
	#[error("Transaction Retrieval Failure: Unable to retrieve ancestral data for TX {txid}: {error}")]
	AncestorRetrievalFailure {
		txid: Txid,
		error: String
	},

	#[error("Block Retrieval Failure: Unable to retrieve a block at height {height}: {error}")]
	BlockRetrievalFailure { height: BlockHeight, error: String },

	#[error("Claim Missing Inputs: No inputs given to claim")]
	ClaimMissingInputs,

	#[error("Claim Fee Exceeds Output: Cost to claim exits was {needed}, but the total output was {output}")]
	ClaimFeeExceedsOutput {
		needed: Amount,
		output: Amount,
	},

	#[error("Claim Signing Error: Unable to sign claim: {error}")]
	ClaimSigningError { error: String },

	#[error("Cyclic Exit Transactions Error: The exit transactions for VTXO {vtxo} are cyclic")]
	CyclicExitTransactions {
		vtxo: VtxoId
	},

	#[error("Database Store Failure: Unable to update exit VTXO {vtxo_id} in the database: {error}")]
	DatabaseVtxoStoreFailure {
		vtxo_id: VtxoId,
		error: String
	},

	#[error("Database Retrieval Failure: Unable to get child tx: {error}")]
	DatabaseChildRetrievalFailure { error: String },

	#[error("Dust Limit Error: The dust limit for a VTXO is {dust} but the balance is only {vtxo}")]
	DustLimit {
		vtxo: Amount,
		dust: Amount
	},

	#[error("Exit Package Broadcast Failure: Unable to broadcast exit transaction package {txid}: {error}")]
	ExitPackageBroadcastFailure {
		txid: Txid,
		error: String
	},

	#[error("Exit Package Finalize Failure: Unable to create exit transaction package: {error}")]
	ExitPackageFinalizeFailure { error: String },

	#[error("Exit Package Store Failure: Unable to store exit transaction package {txid}: {error}")]
	ExitPackageStoreFailure {
		txid: Txid,
		error: String
	},

	#[error("Insufficient Confirmed Funds: {needed} is needed but only {available} is available")]
	InsufficientConfirmedFunds {
		needed: Amount,
		available: Amount
	},

	#[error("Insufficient Fee Error: Your balance is {balance} but an estimated {total_fee} (fee rate of {fee_rate}) is required to exit the VTXO")]
	InsufficientFeeToStart {
		balance: Amount,
		total_fee: Amount,
		fee_rate: FeeRate,
	},

	#[error("Internal Error: An unexpected problem occurred, {error}")]
	InternalError { error: String },

	#[error("Invalid Exit Transaction Status: Exit tx {txid} has an invalid status ({status}): {error}")]
	InvalidExitTransactionStatus {
		txid: Txid,
		status: ExitTxStatus,
		error: String
	},

	#[error("Invalid Local Locktime: {error}")]
	InvalidLocalLocktime {
		tip: BlockHeight,
		error: String
	},

	#[error("Invalid Wallet State: {error}")]
	InvalidWalletState { error: String },

	#[error("Missing Anchor Output: Malformed exit tx {txid}")]
	MissingAnchorOutput { txid: Txid },

	#[error("Missing VTXO Transaction: Couldn't find exit tx {txid}")]
	MissingExitTransaction { txid: Txid },

	#[error("Movement Registration Failure: {error}")]
	MovementRegistrationFailure { error: String },

	#[error("Tip Retrieval Failure: Unable to retrieve the blockchain tip height: {error}")]
	TipRetrievalFailure { error: String },

	#[error("Transaction Retrieval Failure: Unable to check the status of TX {txid}: {error}")]
	TransactionRetrievalFailure { txid: Txid, error: String },

	#[error("VTXO Not Spendable Error: Attempted to claim a VTXO which is not in a spendable state: {vtxo}")]
	VtxoNotClaimable { vtxo: VtxoId },

	#[error("VTXO ScriptPubKey Invalid: {error}")]
	VtxoScriptPubKeyInvalid { error: String },
}

impl From<FromScriptError> for ExitError {
	fn from(e: FromScriptError) -> Self {
		ExitError::VtxoScriptPubKeyInvalid { error: e.to_string() }
	}
}
