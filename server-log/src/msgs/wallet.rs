
use std::{time::Duration, borrow::Cow};

use bdk_wallet::Balance;
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::address::{Address, NetworkUnchecked};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUnchanged {
	pub wallet: Cow<'static, str>,
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUnchanged, TRACE, "Wallet balance has not unchanged since the previous sync");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalanceUpdated {
	pub wallet: Cow<'static, str>,
	pub balance: Balance,
	pub block_height: u32,
}
impl_slog!(WalletBalanceUpdated, INFO, "Wallet balance has changed");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncStarting {
	pub wallet: Cow<'static, str>,
	pub block_height: u32,
}
impl_slog!(WalletSyncStarting, DEBUG, "Starting onchain sync of wallet");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncCommittingProgress {
	pub wallet: Cow<'static, str>,
	pub block_height: u32,
}
impl_slog!(WalletSyncCommittingProgress, DEBUG, "Wallet partially synced, committing changes to the database");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSyncComplete {
	pub wallet: Cow<'static, str>,
	pub new_block_height: u32,
	pub previous_block_height: u32,
	#[serde(with = "crate::serde_utils::duration_millis")]
	pub sync_time: Duration,
	pub next_address: Address<NetworkUnchecked>,
}
impl_slog!(WalletSyncComplete, DEBUG, "Wallet synced to latest block");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletTransactionBroadcastFailure {
	pub wallet: Cow<'static, str>,
	pub error: String,
	pub txid: Txid,
}
impl_slog!(WalletTransactionBroadcastFailure, WARN, "Failed to broadcast unconfirmed transaction");

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletSignedTx {
	pub wallet: Cow<'static, str>,
	pub txid: Txid,
	pub inputs: Vec<OutPoint>,
	#[serde(with = "crate::serde_utils::hex")]
	pub raw_tx: Vec<u8>,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub fee: Amount,
}
impl_slog!(WalletSignedTx, DEBUG, "Our wallet signed an onchain tx");
