
use bitcoin::{Amount, OutPoint};
use bitcoin::secp256k1::PublicKey;

use ark::{Vtxo, VtxoId};
use ark::vtxo::VtxoPolicyType;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct InvoiceInfo {
	pub invoice: String,
}

/// Struct representing information about an Unspent Transaction Output (UTXO).
///
/// This structure provides details about a UTXO, which includes the outpoint (transaction ID and
/// index), the associated amount in satoshis, and the block height at which the transaction was
/// confirmed (if available).
///
/// # Serde Behavior
///
/// * The `amount` field is serialized and deserialized with a custom function from the `bitcoin`
///   crate that ensures the value is interpreted as satoshis with the name `amount_sat`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct UtxoInfo {
	/// Contains the reference to the specific transaction output via transaction ID and index.
	pub outpoint: OutPoint,
	/// The value of the UTXO in satoshis.
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// An optional field that specifies the block height at which the transaction was confirmed. If
	/// the transaction is unconfirmed, this value will be `None`.
	pub confirmation_height: Option<u32>,
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
	pub chain_anchor: OutPoint,
	pub exit_depth: u16,
	pub arkoor_depth: u16,
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
			chain_anchor: v.chain_anchor(),
			exit_depth: v.exit_depth(),
			arkoor_depth: v.arkoor_depth(),
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
