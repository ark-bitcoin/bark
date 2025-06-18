
use std::borrow::Borrow;
use std::collections::BTreeMap;

use bitcoin::TxOut;
use cbitcoin::{
	taproot, Amount, Denomination, FeeRate, OutPoint, ScriptBuf, Transaction, WitnessVersion,
};
use cbitcoin::script::{Builder, PushBytes};
use cbitcoin::taproot::ControlBlock;
use cbitcoin::secp256k1::{self, Keypair, Secp256k1};

use crate::fee;

/// Extension trait for [Keypair].
pub trait KeypairExt: Borrow<Keypair> {
	/// Adapt this key pair to be used in a key-spend-only taproot.
	fn for_keyspend(&self, secp: &Secp256k1<impl secp256k1::Verification>) -> Keypair {
		let tweak = taproot::TapTweakHash::from_key_and_tweak(
			self.borrow().x_only_public_key().0,
			None, // keyspend has no script merkle root
		);
		self.borrow().add_xonly_tweak(secp, &tweak.to_scalar()).expect("hashed values")
	}
}
impl KeypairExt for Keypair {}


/// Extension trait for [Transaction].
pub trait TransactionExt: Borrow<Transaction> {
	/// Check if this tx has a fee anchor output and return the outpoint of it.
	fn fee_anchor(&self) -> Option<(OutPoint, &TxOut)> {
		for (i, out) in self.borrow().output.iter().enumerate() {
			if out.script_pubkey == *fee::P2A_SCRIPT {
				let point = OutPoint::new(self.borrow().compute_txid(), i as u32);
				return Some((point, out));
			}
		}
		None
	}

	/// Returns total output value of the transaction.
	fn output_value(&self) -> Amount {
		self.borrow().output.iter().map(|o| o.value).sum()
	}

	/// Returns an iterator over all input and output UTXOs related to this tx.
	fn all_related_utxos(&self) -> impl Iterator<Item = OutPoint> {
		let tx = self.borrow();
		let inputs = tx.input.iter().map(|i| i.previous_output);
		let txid = tx.compute_txid();
		let outputs = (0..tx.output.len()).map(move |idx| OutPoint::new(txid, idx as u32));
		inputs.chain(outputs)
	}
}
impl TransactionExt for Transaction {}


/// An extension trait for [taproot::TaprootSpendInfo].
pub trait TaprootSpendInfoExt: Borrow<taproot::TaprootSpendInfo> {
	/// Return the existing tapscripts in the format that PSBT expects.
	fn psbt_tap_scripts(&self) -> BTreeMap<ControlBlock, (ScriptBuf, taproot::LeafVersion)> {
		let s = self.borrow();
		s.script_map().keys().map(|pair| {
			let cb = s.control_block(pair).unwrap();
			let (ref script, leaf_version) = pair;
			(cb, (script.clone(), *leaf_version))
		}).collect()
	}
}
impl TaprootSpendInfoExt for taproot::TaprootSpendInfo {}

/// Extension trait for [Amount].
pub trait AmountExt: Borrow<Amount> {
	fn to_msat(&self) -> u64 {
		self.borrow().to_sat() * 1_000
	}

	/// Convert an amount from msat, rounding up.
	fn from_msat_ceil(value: u64) -> Amount {
		Amount::from_sat((value + 999) / 1_000)
	}

	/// Convert an amount from msat, rounding down.
	fn from_msat_floor(value: u64) -> Amount {
		Amount::from_sat(value / 1_000)
	}
}
impl AmountExt for Amount {}


/// Extension trait for [FeeRate].
pub trait FeeRateExt: Borrow<FeeRate> {
	fn from_amount_per_kvb(amount_vkb: Amount) -> FeeRate {
		FeeRate::from_sat_per_kvb(amount_vkb.to_sat())
	}

	fn from_sat_per_kvb(sat_kvb: u64) -> FeeRate {
		FeeRate::from_sat_per_kwu(sat_kvb * 4)
	}

	fn from_sat_per_vb_decimal_checked(sat_vb: f64) -> Option<FeeRate> {
		// Convert to sats per Wu then into kWu to maintain precision
		let fee = (sat_vb * 4.0 * 1000.0).ceil();
		if fee.is_finite() && fee >= 0.0 && fee <= u64::MAX as f64 {
			Some(FeeRate::from_sat_per_kwu(fee as u64))
		} else {
			None
		}
	}

	fn to_btc_per_kvb(&self) -> String {
		Amount::from_sat(self.to_sat_per_kvb()).to_string_in(Denomination::Bitcoin)
	}

	fn to_sat_per_kvb(&self) -> u64 {
		(self.borrow().to_sat_per_kwu() as f64 / 4.0).ceil() as u64
	}
}
impl FeeRateExt for FeeRate {}


/// The P2A program which is given by 0x4e73.
pub(crate) const P2A_PROGRAM: [u8; 2] = [78, 115];

/// Generates P2WSH-type of scriptPubkey with a given [`WitnessVersion`] and the program bytes.
/// Does not do any checks on version or program length.
///
/// Convenience method used by `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
/// Convenience method used by `new_p2a`, `new_p2wpkh`, `new_p2wsh`, `new_p2tr`, and `new_p2tr_tweaked`.
pub(crate) fn new_witness_program_unchecked<T: AsRef<PushBytes>>(
	version: WitnessVersion,
	program: T,
) -> ScriptBuf {
	let program = program.as_ref();
	debug_assert!(program.len() >= 2 && program.len() <= 40);
	// In SegWit v0, the program must be 20 or 32 bytes long.
	// In SegWit v0, the program must be either 20 (P2WPKH) bytes or 32 (P2WSH) bytes long
	debug_assert!(version != WitnessVersion::V0 || program.len() == 20 || program.len() == 32);
	Builder::new().push_opcode(version.into()).push_slice(program).into_script()
}

pub trait ScriptBufExt {
	/// Generates pay to anchor output.
	fn new_p2a() -> Self;
}

impl ScriptBufExt for ScriptBuf {
	/// Generates pay to anchor output.
	fn new_p2a() -> Self {
		new_witness_program_unchecked(WitnessVersion::V1, P2A_PROGRAM)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use cbitcoin::Weight;

	#[test]
	fn amount_from_msat() {
		assert_eq!(Amount::from_msat_ceil(3000), Amount::from_sat(3));
		assert_eq!(Amount::from_msat_ceil(3001), Amount::from_sat(4));
		assert_eq!(Amount::from_msat_ceil(3999), Amount::from_sat(4));

		assert_eq!(Amount::from_msat_floor(3000), Amount::from_sat(3));
		assert_eq!(Amount::from_msat_floor(3001), Amount::from_sat(3));
		assert_eq!(Amount::from_msat_floor(3999), Amount::from_sat(3));
	}

	#[test]
	fn fee_rate_from_amount_per_kvb() {
		assert_eq!(FeeRate::from_amount_per_kvb(Amount::from_sat(1_000)),
			FeeRate::from_sat_per_kwu(Weight::from_vb(1_000).unwrap().to_wu())
		);
		assert_eq!(FeeRate::from_amount_per_kvb(Amount::from_sat(7_372)),
			FeeRate::from_sat_per_kwu(Weight::from_vb(7_372).unwrap().to_wu())
		);
		assert_eq!(FeeRate::from_amount_per_kvb(Amount::from_sat(238)),
			FeeRate::from_sat_per_kwu(Weight::from_vb(238).unwrap().to_wu())
		);
	}

	#[test]
	fn fee_rate_from_sat_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kvb(1_000),
			FeeRate::from_sat_per_kwu(Weight::from_vb(1_000).unwrap().to_wu())
		);
		assert_eq!(FeeRate::from_sat_per_kvb(7_372),
			FeeRate::from_sat_per_kwu(Weight::from_vb(7_372).unwrap().to_wu())
		);
		assert_eq!(FeeRate::from_sat_per_kvb(238),
			FeeRate::from_sat_per_kwu(Weight::from_vb(238).unwrap().to_wu())
		);
	}

	#[test]
	fn fee_rate_from_sat_per_vb_decimal_checked() {
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked(-1.0), None);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked(-15_4921.0), None);

		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked(1.0),
			Some(FeeRate::from_sat_per_kwu(Weight::from_vb(1000).unwrap().to_wu()))
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked(7.372),
			Some(FeeRate::from_sat_per_kwu(Weight::from_vb(7_372).unwrap().to_wu()))
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked(0.238),
			Some(FeeRate::from_sat_per_kwu(Weight::from_vb(238).unwrap().to_wu()))
		);
	}

	#[test]
	fn fee_rate_to_btc_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kwu(4_000).to_btc_per_kvb(), "0.00001");
		assert_eq!(FeeRate::from_sat_per_kwu(29_488).to_btc_per_kvb(), "0.00007372");
		assert_eq!(FeeRate::from_sat_per_kwu(952).to_btc_per_kvb(), "0.00000238");
	}

	#[test]
	fn fee_rate_to_sat_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kwu(4_000).to_sat_per_kvb(), 1_000);
		assert_eq!(FeeRate::from_sat_per_kwu(29_488).to_sat_per_kvb(), 7_372);
		assert_eq!(FeeRate::from_sat_per_kwu(952).to_sat_per_kvb(), 238);
	}
}
