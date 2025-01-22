
use bitcoin::Amount;
use crate::primitives::{VtxoInfo, UtxoInfo};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Balance {
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub onchain: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub offchain: Amount,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub pending_exit: Amount,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExitStatus {
	pub done: bool,
	pub height: Option<u32>,
}

pub mod onchain {
	use super::*;

	#[derive(Debug, Clone, Deserialize, Serialize)]
	pub struct Send {
		pub txid: bitcoin::Txid,
	}

	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct Address {
		pub address: bitcoin::Address<bitcoin::address::NetworkUnchecked>,
	}

	pub type Utxos = Vec<UtxoInfo>;

	#[derive(Debug, Clone, Serialize, Deserialize)]
	pub struct Balance {
		#[serde(rename="total_sat", with="bitcoin::amount::serde::as_sat")]
		pub total: bitcoin::Amount
	}
}

pub type Vtxos = Vec<VtxoInfo>;
