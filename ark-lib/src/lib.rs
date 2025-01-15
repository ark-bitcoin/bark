
pub extern crate bitcoin;

#[macro_use] extern crate serde;
#[macro_use] extern crate lazy_static;

pub mod connectors;
pub mod fee;
pub mod forfeit;
pub mod lightning;
pub mod musig;
pub mod onboard;
pub mod oor;
pub mod tree;
pub mod util;
pub mod vtxo;

#[cfg(test)]
mod napkin;


use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxOut, Weight};
use bitcoin::secp256k1::PublicKey;

pub use crate::vtxo::{ArkoorVtxo, Bolt11ChangeVtxo, OnboardVtxo, RoundVtxo, VtxoId, VtxoSpec, Vtxo};


pub const P2TR_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2TR_DUST_SAT: u64 = P2TR_DUST_VB * 3;
pub const P2TR_DUST: Amount = Amount::from_sat(P2TR_DUST_SAT);

pub const P2WPKH_DUST_VB: u64 = 90;
/// 294 satoshis
pub const P2WPKH_DUST_SAT: u64 = P2WPKH_DUST_VB * 3;
pub const P2WPKH_DUST: Amount = Amount::from_sat(P2WPKH_DUST_SAT);

pub const P2PKH_DUST_VB: u64 = 182;
/// 546 satoshis
pub const P2PKH_DUST_SAT: u64 = P2PKH_DUST_VB * 3;
pub const P2PKH_DUST: Amount = Amount::from_sat(P2PKH_DUST_SAT);

pub const P2SH_DUST_VB: u64 = 180;
/// 540 satoshis
pub const P2SH_DUST_SAT: u64 = P2PKH_DUST_VB * 3;
pub const P2SH_DUST: Amount = Amount::from_sat(P2SH_DUST_SAT);

pub const P2WSH_DUST_VB: u64 = 110;
/// 330 satoshis
pub const P2WSH_DUST_SAT: u64 = P2TR_DUST_VB * 3;
pub const P2WSH_DUST: Amount = Amount::from_sat(P2WSH_DUST_SAT);

/// Witness weight of a taproot keyspend.
pub const TAPROOT_KEYSPEND_WEIGHT: usize = 66;


/// Type representing a block height in the bitcoin blockchain.
pub type BlockHeight = u64;

/// Request for the creation of a VTXO.
///
/// NB This differs from the [VtxoRequest] type in ark-lib in the fact that
/// it doesn't have a cosign pubkey attached yet.
/// With covenants we can remove this type distinction.
/// Or we might be able to use it for OOR payments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct PaymentRequest {
	pub pubkey: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct VtxoRequest {
	pub pubkey: PublicKey,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
	/// The public key used by the client to cosign the transaction tree
	/// The client SHOULD forget this key after signing it
	pub cosign_pk: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct OffboardRequest {
	pub script_pubkey: ScriptBuf,
	#[serde(with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount,
}

impl OffboardRequest {
	pub fn calculate_fee(script: &Script, fee_rate: FeeRate) -> Option<Amount> {
		// NB We calculate the required extra fee as the "dust" fee for the given feerate.
		// We take Bitcoin's dust amounts, which are calculated at 3 sat/vb, but then
		// calculated for the given feerate. For more on dust, see:
		// https://bitcoin.stackexchange.com/questions/10986/what-is-meant-by-bitcoin-dust

		let vb = if script.is_p2pkh() {
			P2PKH_DUST_VB
		} else if script.is_p2sh() {
			P2SH_DUST_VB
		} else if script.is_p2wpkh() {
			P2WPKH_DUST_VB
		} else if script.is_p2wsh() {
			P2WSH_DUST_VB
		} else if script.is_p2tr() {
			P2TR_DUST_VB
		} else if script.is_op_return() {
			//TODO(stevenroose) verify length limit of standardness rules
			bitcoin::consensus::encode::VarInt(script.len() as u64).size() as u64
				+ script.len() as u64
				+ 8
				// the input data (scriptSig and witness length fields included)
				+ 36 + 4 + 1 + 1
		} else {
			return None;
		};
		Some(fee_rate * Weight::from_vb(vb).expect("no overflow"))
	}

	/// Validate that the offboard has a valid script.
	pub fn validate(&self) -> Result<(), &'static str> {
		if Self::calculate_fee(&self.script_pubkey, FeeRate::ZERO).is_none() {
			Err("invalid script")
		} else {
			Ok(())
		}
	}

	/// Convert into a tx output.
	pub fn to_txout(&self) -> TxOut {
		TxOut {
			script_pubkey: self.script_pubkey.clone(),
			value: self.amount,
		}
	}

	/// Returns the fee charged for the user to make this offboard given the fee rate.
	///
	/// Always returns [Some] if [OffboardRequest::validate] returns [Ok].
	pub fn fee(&self, fee_rate: FeeRate) -> Option<Amount> {
		Self::calculate_fee(&self.script_pubkey, fee_rate)
	}
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VtxoSubset {
	pub id: VtxoId,
	#[serde(rename = "amount_sat", with = "bitcoin::amount::serde::as_sat")]
	pub amount: Amount
}

/// A [`Movement`] represents any balance change, it can be of three kinds.
///
/// ### Incoming payment
/// The wallet receives a new VTXO: the balance increases.
/// The resulting movement will only have `receives` field filled
///
/// ### Outgoing payment
/// The wallet sends a set of VTXOs: the balance decreases.
/// The resulting movement will reference spent VTXOs in `spends` field,
/// change VTXO in `receives` one and a non-null destination (either pubkey or BOLT11)
///
/// ### Refreshes
/// Wallet's VTXOs are replaced by new ones, and a small fee is paid: the balance decreases.
/// The resulting movement will reference refreshed VTXOs in `spends` field,
/// new ones in `receives`, and no destination.
#[derive(Debug, Deserialize, Serialize)]
pub struct Movement {
	pub id: u32,
	/// Can either be a publickey or a bolt11 invoice
	///
	/// Paid amount can be computed as: `paid = sum(spends) - sum(receives) - fees`
	pub destination: Option<String>,
	/// Fees paid for the movement
	pub fees: Amount,
	/// wallet's VTXOs spent in this movement
	pub spends: Vec<VtxoSubset>,
	/// Received VTXOs from this movement
	pub receives: Vec<VtxoSubset>,
	/// Movement date
	pub created_at: String,
}
