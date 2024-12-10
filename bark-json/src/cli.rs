

use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::PublicKey;

use ark::{VtxoId, Vtxo};


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UtxoInfo {
	pub outpoint: OutPoint,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub confirmation_height: Option<u32>
}

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
#[serde(rename_all = "lowercase")]
pub enum VtxoType {
	Onboard,
	Round,
	Oor,
	Bolt11Change,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VtxoInfo {
	pub id: VtxoId,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub vtxo_type: VtxoType,
	/// The offchain UTXO.
	pub utxo: OutPoint,
	pub user_pubkey: PublicKey,
	pub asp_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
}

impl From<Vtxo> for VtxoInfo {
	fn from(v: Vtxo) -> VtxoInfo {
		VtxoInfo {
			id: v.id(),
			amount: v.amount(),
			vtxo_type: match v {
				Vtxo::Onboard { .. } => VtxoType::Onboard,
				Vtxo::Round { .. } => VtxoType::Round,
				Vtxo::Oor { .. } => VtxoType::Oor,
				Vtxo::Bolt11Change { .. } => VtxoType::Bolt11Change,
			},
			utxo: v.point(),
			user_pubkey: v.spec().user_pubkey,
			asp_pubkey: v.spec().asp_pubkey,
			expiry_height: v.spec().expiry_height,
			exit_delta: v.spec().exit_delta,
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExitStatus {
	pub done: bool,
	pub height: Option<u32>,
}
