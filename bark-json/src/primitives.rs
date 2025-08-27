
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::PublicKey;

use ark::{Vtxo, VtxoId};
use ark::vtxo::VtxoPolicyType;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InvoiceInfo {
	pub invoice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UtxoInfo {
	pub outpoint: OutPoint,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub confirmation_height: Option<u32>

}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VtxoInfo {
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub policy_type: VtxoPolicyType,
	pub user_pubkey: PublicKey,
	pub server_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
}

impl From<Vtxo> for VtxoInfo {
	fn from(v: Vtxo) -> VtxoInfo {
		VtxoInfo {
			id: v.id(),
			amount: v.amount(),
			policy_type: v.policy().policy_type(),
			user_pubkey: v.user_pubkey(),
			server_pubkey: v.server_pubkey(),
			expiry_height: v.expiry_height(),
			exit_delta: v.exit_delta(),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct RecipientInfo {
	/// Can either be a publickey, spk or a bolt11 invoice
	pub recipient: String,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}
