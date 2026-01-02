//! Onchain wallet integration interfaces.
//!
//! This module defines the traits and types that an external onchain wallet must
//! implement to be used by the library. The goal is to let integrators plug in
//! their own wallet implementation, so features like boarding (moving onchain funds
//! into Ark) and unilateral exit (claiming VTXOs onchain without server cooperation)
//! are supported.
//!
//! Key concepts exposed here:
//! - [Utxo], [LocalUtxo] & [SpendableExit]: lightweight types representing wallet UTXOs and
//!   spendable exit outputs.
//! - [PreparePsbt] & [SignPsbt]: funding and signing interfaces for building transactions.
//! - [GetBalance], [GetWalletTx], [GetSpendingTx]: read-access to wallet state for balance
//!   and [Transaction] lookups required by various parts of the library.
//! - [MakeCpfp]: CPFP construction interfaces used for create child transactions.
//! - [ExitUnilaterally]: a convenience trait that aggregates the required capabilities a
//!   wallet must provide to support unilateral exits.
//!
//! A reference implementation based on BDK is available behind the `onchain_bdk`
//! cargo feature. Enable it to use the provided [OnchainWallet] implementation.
//! You can use all features from BDK because [bdk_wallet] is re-exported.

#[cfg(feature = "onchain_bdk")]
mod bdk;

#[cfg(feature = "onchain_bdk")]
pub use bdk_wallet;

pub use bitcoin_ext::cpfp::{CpfpError, MakeCpfpFees};

/// BDK-backed onchain wallet implementation.
///
/// Available only when the `onchain_bdk` feature is enabled.
#[cfg(feature = "onchain_bdk")]
pub use crate::onchain::bdk::{OnchainWallet, TxBuilderExt};

use std::sync::Arc;

use bitcoin::{
	Address, Amount, FeeRate, OutPoint, Psbt, Transaction, Txid
};

use ark::Vtxo;
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::chain::ChainSource;

/// Represents an onchain UTXO known to the wallet.
///
/// This can be either:
/// - `Local`: a standard wallet UTXO
/// - `Exit`: a spendable exit output produced by the Ark exit mechanism
#[derive(Debug, Clone)]
pub enum Utxo {
	Local(LocalUtxo),
	Exit(SpendableExit),
}

/// A standard wallet [Utxo] owned by the local wallet implementation.
#[derive(Debug, Clone)]
pub struct LocalUtxo {
	/// The outpoint referencing the UTXO.
	pub outpoint: OutPoint,
	/// The amount contained in the UTXO.
	pub amount: Amount,
	/// Optional confirmation height; `None` if unconfirmed.
	pub confirmation_height: Option<BlockHeight>,
}

/// A spendable unilateral exit of a [Vtxo] which can be claimed onchain.
///
/// When exiting unilaterally, the wallet will end up with onchain outputs that correspond to
/// previously-held VTXOs. These can be claimed and used for further spending.
#[derive(Debug, Clone)]
pub struct SpendableExit {
	/// The VTXO being exited.
	pub vtxo: Vtxo,
	/// The block height associated with the exits' validity window.
	pub height: BlockHeight,
}

/// Ability to finalize a [Psbt] into a fully signed [Transaction].
///
/// Wallets should apply all necessary signatures and finalize inputs according
/// to their internal key management and policies.
pub trait SignPsbt {
	/// Consume a [Psbt] and return a fully signed and finalized [Transaction].
	fn finish_tx(&mut self, psbt: Psbt) -> anyhow::Result<Transaction>;
}

/// Ability to query the wallets' total balance.
///
/// This is used by higher-level flows to decide when onchain funds are available for boarding or
/// fee bumping, and to present balance information to users.
pub trait GetBalance {
	/// Get the total balance of the wallet.
	fn get_balance(&self) -> Amount;
}

/// Ability to look up transactions known to the wallet.
///
/// Implementations should return wallet-related transactions and, when possible,
/// the block information those transactions confirmed in.
pub trait GetWalletTx {
	/// Retrieve the wallet [Transaction] for the given [Txid] if any.
	fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>>;

	/// Retrieve information about the block, if any, a given wallet transaction was confirmed in.
	fn get_wallet_tx_confirmed_block(&self, txid: Txid) -> anyhow::Result<Option<BlockRef>>;
}

/// Ability to construct funded PSBTs for specific destinations or to drain the wallet.
///
/// These methods are used to build transactions for boarding, exits, and fee bumping.
pub trait PreparePsbt {
	/// Prepare a [Transaction] which will send to the given destinations.
	fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Prepare a [Transaction] for sending all wallet funds to the given destination.
	fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;
}

/// Ability to find wallet-local spends of a specific [OutPoint].
///
/// This helps identify if the wallet has already spent an exit or parent [Transaction].
pub trait GetSpendingTx {
	/// This should search the wallet and look for any [Transaction] that spends the given
	/// [OutPoint]. The intent of the function is to only look at spends which happen in the wallet
	/// itself.
	fn get_spending_tx(&self, outpoint: OutPoint) -> Option<Arc<Transaction>>;
}

/// Ability to create and persist CPFP transactions for spending P2A outputs.
pub trait MakeCpfp {
	/// Creates a signed Child Pays for Parent (CPFP) transaction using a Pay-to-Anchor (P2A) output
	/// to broadcast unilateral exits and other TRUC transactions.
	///
	/// For more information please see [BIP431](https://github.com/bitcoin/bips/blob/master/bip-0431.mediawiki#topologically-restricted-until-confirmation).
	///
	/// # Arguments
	///
	/// * `tx` - A parent `Transaction` that is guaranteed to have one P2A output which
	///          implementations must spend so that both the parent and child transactions can be
	///          broadcast to the network as a v3 transaction package.
	/// * `fees` - Informs the implementation how fees should be paid by the child transaction. Note
	///            that an effective fee rate should be calculated using the weight of both the
	///            parent and child transactions.
	///
	/// # Returns
	///
	/// Returns a `Result` containing:
	/// * `Transaction` - The signed CPFP transaction ready to be broadcasted to the network with
	///                   the given parent transaction if construction and signing were successful.
	/// * `CpfpError` - An error indicating the reason for failure in constructing the CPFP
	///                 transaction (e.g., insufficient funds, invalid parent transaction, or
	///                 signing failure).
	fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError>;

	/// Persist the signed CPFP transaction so it can be rebroadcast or retrieved as needed.
	fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError>;
}

/// Trait alias for wallets that support boarding.
///
/// Any wallet type implementing these component traits automatically implements
/// `Board`. The trait requires Send + Sync because boarding flows may be
/// executed from async tasks and across threads.
///
/// Required capabilities:
/// - [SignPsbt]: to finalize transactions
/// - [GetWalletTx]: to query related transactions and their confirmations
/// - [PreparePsbt]: to prepare transactions for boarding
pub trait Board: PreparePsbt + SignPsbt + GetWalletTx + Send + Sync {}

impl <W: PreparePsbt + SignPsbt + GetWalletTx + Send + Sync> Board for W {}

/// Trait alias for wallets that support unilateral exit end-to-end.
///
/// Any wallet type implementing these component traits automatically implements
/// `ExitUnilaterally`. The trait requires Send + Sync because exit flows may be
/// executed from async tasks and across threads.
///
/// Required capabilities:
/// - [GetBalance]: to evaluate available funds
/// - [GetWalletTx]: to query related transactions and their confirmations
/// - [MakeCpfp]: to accelerate slow/pinned exits
/// - [SignPsbt]: to finalize transactions
/// - [GetSpendingTx]: to detect local spends relevant to exit coordination
pub trait ExitUnilaterally:
	GetBalance +
	GetWalletTx +
	MakeCpfp +
	SignPsbt +
	GetSpendingTx +
	Send + Sync + {}

impl <W: GetBalance +
	GetWalletTx +
	MakeCpfp +
	SignPsbt +
	GetSpendingTx +
	Send + Sync> ExitUnilaterally for W {}

/// Ability to sync the wallet with the onchain network.
#[tonic::async_trait]
pub trait ChainSync {
	/// Sync the wallet with the onchain network.
	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()>;
}
