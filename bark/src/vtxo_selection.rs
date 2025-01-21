use ark::Vtxo;
use bdk_wallet::WalletPersister;

use serde::ser::StdError;
use crate::{persist::BarkPersister, Wallet};

/// Trait needed to be implemented to select wallet VTXOs
///
/// See [`Wallet::vtxos_with`]
pub trait SelectVtxo {
	fn select<'a>(&self, all: &'a [Vtxo]) -> Vec<Vtxo>;
}

/// A struct used to select VTXOs that will be get expired at a given height
pub struct ExpiredAtHeight(pub u32);

impl SelectVtxo for ExpiredAtHeight {
	fn select<'a>(&self, vtxos: &'a [Vtxo]) -> Vec<Vtxo> {
		vtxos
			.to_owned()
			.into_iter()
			.filter(|v| self.0 > v.spec().expiry_height)
			.collect::<Vec<_>>()
	}
}

/// A struct used to select VTXOs that have a counterparty risk
pub struct WithCounterpartyRisk<'a, P> where P: BarkPersister {
	pub wallet: &'a Wallet<P>
}

impl <P>SelectVtxo for WithCounterpartyRisk<'_, P>
	where
		P: BarkPersister,
		<P as WalletPersister>::Error: 'static + std::fmt::Debug + std::fmt::Display + Send + Sync + StdError
	{
	fn select<'a>(&self, vtxos: &'a [Vtxo]) -> Vec<Vtxo> {
		vtxos
			.to_owned()
			.into_iter()
			.filter(|v| v.has_counterparty_risk(&self.wallet.vtxo_pubkey()))
			.collect::<Vec<_>>()
	}
}