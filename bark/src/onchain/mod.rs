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
//! - [OnchainWalletTrait]: unified interface covering balance, address, PSBT construction and signing,
//!   transaction lookups, and CPFP fee-bumping for unilateral exits.
//!
//! A reference implementation based on BDK is available behind the `onchain-bdk`
//! cargo feature. Enable it to use the provided [OnchainWallet] implementation.
//! You can use all features from BDK because [bdk_wallet] is re-exported.

#[cfg(feature = "onchain-bdk")]
mod bdk;

#[cfg(feature = "onchain-bdk")]
pub use bdk_wallet;

pub use bitcoin_ext::cpfp::{CpfpError, MakeCpfpFees};

/// BDK-backed onchain wallet implementation.
///
/// Available only when the `onchain-bdk` feature is enabled.
#[cfg(feature = "onchain-bdk")]
pub use crate::onchain::bdk::{OnchainWallet, TxBuilderExt};

use std::sync::Arc;

use bitcoin::{
	Address, Amount, FeeRate, OutPoint, Psbt, Script, SignedAmount, Transaction, Txid,
};

use ark::Vtxo;
use ark::vtxo::Full;
use bitcoin_ext::{BlockHeight, BlockRef};

use crate::chain::ChainSource;


/// Summary of a wallet transaction produced by [OnchainWallet::list_transaction_infos].
#[derive(Debug, Clone)]
pub struct WalletTxInfo {
	pub txid: Txid,
	pub tx: Arc<Transaction>,
	/// Total fee paid by the transaction, when computable. `None` for inbound or
	/// collaboratively-funded txs whose foreign prevouts BDK has not indexed
	/// (e.g. after a bitcoind-rpc sync — esplora syncs populate prevouts).
	pub onchain_fees: Option<Amount>,
	/// Net change to the wallet's balance: `received - sent` over wallet-owned outputs.
	pub balance_change: SignedAmount,
	/// `Some` if the transaction is confirmed in a block, `None` if still in the mempool.
	pub confirmation: Option<BlockRef>,
	/// `true` when this tx spends a P2A fee anchor — i.e. it is a CPFP child
	/// bumping the parent that created the anchor.
	pub is_cpfp: bool,
}

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
	pub vtxo: Vtxo<Full>,
	/// The block height associated with the exits' validity window.
	pub height: BlockHeight,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait OnchainWalletTrait: std::any::Any + Send + Sync {
	/// Get the total balance of the wallet
	async fn balance(&self) -> Amount;

	/// Get an onchain receive address from the wallet
	async fn address(&mut self) -> anyhow::Result<Address>;

	/// Sync the wallet with the onchain network.
	async fn sync(&mut self, chain: &ChainSource) -> anyhow::Result<()>;

	/// Retrieve the wallet [Transaction] for the given [Txid] if any
	async fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>>;

	/// Retrieve information about the block, if any, a given wallet transaction was confirmed in
	async fn get_wallet_tx_confirmed_block(&self, txid: Txid) -> anyhow::Result<Option<BlockRef>>;

	/// Returns `true` if the given script pubkey belongs to the wallet's keychains.
	async fn is_mine(&self, spk: &Script) -> anyhow::Result<bool>;

	/// Register an unconfirmed transaction relevant to the wallet
	async fn register_tx(&mut self, tx: &Transaction) -> anyhow::Result<()>;

	/// Prepare a [Transaction] which will send to the given destinations
	async fn prepare_tx(
		&mut self,
		destinations: &[(Address, Amount)],
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Prepare a [Transaction] for sending all wallet funds to the given destination
	async fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Consume a [Psbt] and return a fully signed [Psbt] with all witnesses filled in
	///
	/// Useful when the signed [Psbt] is needed after signing, e.g. to compute fees
	/// via [Psbt::fee] before extracting the final [Transaction].
	///
	/// Wallets should apply all necessary signatures and finalize inputs according
	/// to their internal key management and policies.
	async fn finish_psbt(&mut self, psbt: Psbt) -> anyhow::Result<Psbt>;

	/// Search the wallet and look for any [Transaction] that spends the given [OutPoint]
	///
	/// The intent of the function is to only look at spends which happen in the wallet
	/// itself.
	async fn get_spending_tx(&self, outpoint: OutPoint) -> Option<Arc<Transaction>>;

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
	async fn make_signed_p2a_cpfp(
		&mut self,
		tx: &Transaction,
		fees: MakeCpfpFees,
	) -> Result<Transaction, CpfpError>;

	/// Persist the signed CPFP transaction so it can be rebroadcast or retrieved as needed.
	async fn store_signed_p2a_cpfp(&mut self, tx: &Transaction) -> anyhow::Result<(), CpfpError>;
}
