use ark::vtxo::VtxoSpkSpec;
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::PublicKey;

use ark::{BoardVtxo, Vtxo, VtxoId};

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
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VtxoType {
	Board,
	Round,
	Arkoor,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct VtxoInfo {
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	pub vtxo_type: VtxoType,
	/// The offchain UTXO.
	pub utxo: OutPoint,
	pub user_pubkey: PublicKey,
	pub asp_pubkey: PublicKey,
	pub expiry_height: u32,
	pub exit_delta: u16,
	pub spk: VtxoSpkSpec,
}

impl From<Vtxo> for VtxoInfo {
	fn from(v: Vtxo) -> VtxoInfo {
		VtxoInfo {
			id: v.id(),
			amount: v.amount(),
			vtxo_type: match v {
				Vtxo::Board { .. } => VtxoType::Board,
				Vtxo::Round { .. } => VtxoType::Round,
				Vtxo::Arkoor { .. } => VtxoType::Arkoor,
			},
			utxo: v.point(),
			user_pubkey: v.spec().user_pubkey,
			asp_pubkey: v.asp_pubkey(),
			expiry_height: v.expiry_height(),
			exit_delta: v.exit_delta(),
			spk: v.spec().spk.clone(),
		}
	}
}

impl From<BoardVtxo> for VtxoInfo {
	fn from(v: BoardVtxo) -> VtxoInfo {
		Vtxo::Board(v).into()
	}
}
