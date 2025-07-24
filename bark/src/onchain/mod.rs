
mod chain;
mod bdk;

pub use crate::onchain::chain::{ChainSource, ChainSourceClient, FeeRates};
pub use crate::onchain::bdk::{OnchainWallet, TxBuilderExt};

use std::sync::Arc;

use bitcoin::{
	Address, Amount, FeeRate, OutPoint, Psbt, Transaction, Txid
};

use ark::Vtxo;
use bitcoin_ext::bdk::CpfpError;
use bitcoin_ext::BlockHeight;

#[derive(Debug, Clone)]
pub enum Utxo {
	Local(LocalUtxo),
	Exit(SpendableExit),
}

#[derive(Debug, Clone)]
pub struct LocalUtxo {
	pub outpoint: OutPoint,
	pub amount: Amount,
	pub confirmation_height: Option<BlockHeight>,
}

#[derive(Debug, Clone)]
pub struct SpendableExit {
	pub vtxo: Vtxo,
	pub height: BlockHeight,
}

/// A trait to support signing transactions with a wallet.
pub trait SignPsbt {
	fn finish_tx(&mut self, psbt: Psbt) -> anyhow::Result<Transaction>;
}

/// A trait to support getting the balance of a wallet.
pub trait GetBalance {
	/// Get the total balance of the wallet.
	fn get_balance(&self) -> Amount;
}

/// A trait to support getting a transaction from a wallet.
pub trait GetWalletTx {
	fn get_wallet_tx(&self, txid: Txid) -> Option<Arc<Transaction>>;
}

/// A trait to support creating funded PSBTs.
pub trait PreparePsbt {
	/// Prepare a funded tx sending to the given destinations.
	fn prepare_tx<T: IntoIterator<Item = (Address, Amount)>>(
		&mut self,
		destinations: T,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;

	/// Prepare a funded tx sending all wallet funds to the given destination.
	fn prepare_drain_tx(
		&mut self,
		destination: Address,
		fee_rate: FeeRate,
	) -> anyhow::Result<Psbt>;
}

pub trait GetSpendingTx {
	fn get_spending_tx(&self, txid: Txid) -> Option<Arc<Transaction>>;
}

pub trait MakeCpfp {
	fn make_p2a_cpfp(&mut self, tx: &Transaction, fee_rate: FeeRate) -> Result<Psbt, CpfpError>;
}

/// Trait for wallets that can be used to unilaterally exit vtxos
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
