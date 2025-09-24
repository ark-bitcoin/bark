
use std::{time::Duration, borrow::Cow};

use bdk_wallet::Balance;
use bitcoin::Txid;
use bitcoin::address::{Address, NetworkUnchecked};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUnchanged {
	pub wallet: Cow<'static, str>,
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUnchanged, Trace, "Wallet balance has not unchanged since the previous sync");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUpdated {
	pub wallet: Cow<'static, str>,
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUpdated, Info, "Wallet balance has changed");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncStarting {
	pub wallet: Cow<'static, str>,
	pub block_height: u32,
}
impl_slog!(WalletSyncStarting, Debug, "Starting onchain sync of wallet");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncCommittingProgress {
	pub wallet: Cow<'static, str>,
	pub block_height: u32,
}
impl_slog!(WalletSyncCommittingProgress, Debug, "Wallet partially synced, committing changes to the database");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncComplete {
	pub wallet: Cow<'static, str>,
	pub new_block_height: u32,
	pub previous_block_height: u32,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub sync_time: Duration,
	pub next_address: Address<NetworkUnchecked>,
}
impl_slog!(WalletSyncComplete, Debug, "Wallet synced to latest block");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionBroadcastFailure {
	pub wallet: Cow<'static, str>,
	pub error: String,
	pub txid: Txid,
}
impl_slog!(WalletTransactionBroadcastFailure, Warn, "Failed to broadcast unconfirmed transaction");
