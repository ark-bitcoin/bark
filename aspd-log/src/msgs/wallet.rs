
use std::time::Duration;

use bdk_wallet::Balance;
use bitcoin::Txid;


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUnchanged {
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUnchanged, Trace, "Wallet balance has not unchanged since the previous sync");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUpdated {
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUpdated, Info, "Wallet balance has changed");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncStarting {
	pub block_height: u32,
}
impl_slog!(WalletSyncStarting, Debug, "Starting onchain sync of wallet");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncCommittingProgress {
	pub block_height: u32,
}
impl_slog!(WalletSyncCommittingProgress, Debug, "Wallet partially synced, committing changes to the database");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncComplete {
	pub new_block_height: u32,
	pub previous_block_height: u32,
	#[serde(with = "crate::serde_utils::duration")]
	pub sync_time: Duration,
}
impl_slog!(WalletSyncComplete, Debug, "Wallet synced to latest block");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionBroadcastFailure {
	pub error: String,
	pub txid: Txid,
}
impl_slog!(WalletTransactionBroadcastFailure, Warn, "Failed to broadcast unconfirmed transaction");
