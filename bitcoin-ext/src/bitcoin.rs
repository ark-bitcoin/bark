
use std::borrow::Borrow;
use std::collections::BTreeMap;

use bitcoin::{
	taproot, Amount, Denomination, FeeRate, OutPoint, ScriptBuf, Transaction, TxOut, Weight,
};
use bitcoin::taproot::ControlBlock;
use bitcoin::secp256k1::{self, Keypair, Secp256k1};

use crate::{fee, P2PKH_DUST, P2SH_DUST, P2TR_DUST, P2WPKH_DUST, P2WSH_DUST};

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


/// Extension trait for [TxOut].
pub trait TxOutExt: Borrow<TxOut> {
	/// Check whether this output is a p2a fee anchor.
	fn is_p2a_fee_anchor(&self) -> bool {
		self.borrow().script_pubkey == *fee::P2A_SCRIPT
	}

	/// Basic standardness check. Might be too strict.
	fn is_standard(&self) -> bool {
		let out = self.borrow();

		let dust_limit = if out.script_pubkey.is_p2pkh() {
			P2PKH_DUST
		} else if out.script_pubkey.is_p2sh() {
			P2SH_DUST
		} else if out.script_pubkey.is_p2wpkh() {
			P2WPKH_DUST
		} else if out.script_pubkey.is_p2wsh() {
			P2WSH_DUST
		} else if out.script_pubkey.is_p2tr() {
			P2TR_DUST
		} else if out.script_pubkey.is_op_return() {
			return out.script_pubkey.len() <= 83;
		} else {
			return false;
		};

		out.value >= dust_limit
	}
}
impl TxOutExt for TxOut {}


/// Extension trait for [Transaction].
pub trait TransactionExt: Borrow<Transaction> {
	/// Check if this tx has a fee anchor output and return the outpoint of it.
	///
	/// Only the first fee anchor is returned.
	fn fee_anchor(&self) -> Option<(OutPoint, &TxOut)> {
		for (i, out) in self.borrow().output.iter().enumerate() {
			if out.is_p2a_fee_anchor() {
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
	/// The p2tr output scriptPubkey for this taproot.
	fn script_pubkey(&self) -> ScriptBuf {
		ScriptBuf::new_p2tr_tweaked(self.borrow().output_key())
	}

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
	fn from_amount_per_kvb_ceil(amount_vkb: Amount) -> FeeRate {
		FeeRate::from_sat_per_kvb_ceil(amount_vkb.to_sat())
	}

	fn from_amount_and_weight_ceil(fee: Amount, weight: Weight) -> Option<FeeRate> {
		if weight == Weight::ZERO {
			return None;
		}

		// Compute the fee rate as amount_sat * 1000 / fee_rate_wu
		let amount_time_thousand = u64::checked_mul(fee.to_sat(), 1_000)?;
		let sat_kwu = u64::div_ceil(amount_time_thousand, weight.to_wu());
		Some(FeeRate::from_sat_per_kwu(sat_kwu))
	}

	fn from_sat_per_kvb_ceil(sat_kvb: u64) -> FeeRate {
		// Adding 3 to sat_kvb ensures we always round up when performing integer division.
		FeeRate::from_sat_per_kwu((sat_kvb + 3) / 4)
	}

	fn from_sat_per_vb_decimal_checked_ceil(sat_vb: f64) -> Option<FeeRate> {
		let fee = (sat_vb * 250.0).ceil();
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
		self.borrow().to_sat_per_kwu() * 4
	}
}
impl FeeRateExt for FeeRate {}


#[cfg(test)]
mod test {
	use super::*;

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
		assert_eq!(FeeRate::from_amount_per_kvb_ceil(Amount::from_sat(1_000)),
			FeeRate::from_sat_per_kwu(250)
		);
		assert_eq!(FeeRate::from_amount_per_kvb_ceil(Amount::from_sat(7_372)),
			FeeRate::from_sat_per_kwu(1_843)
		);
		assert_eq!(FeeRate::from_amount_per_kvb_ceil(Amount::from_sat(238)),
			FeeRate::from_sat_per_kwu(60) // 59.5 rounded up
		);
		assert_eq!(FeeRate::from_amount_per_kvb_ceil(Amount::from_sat(15_775)),
			FeeRate::from_sat_per_kwu(3_944) // 3943.75 rounded up
		);
		assert_eq!(FeeRate::from_amount_per_kvb_ceil(Amount::from_sat(10_125)),
			FeeRate::from_sat_per_kwu(2_532) // 2531.25 rounded up
		);
	}

	#[test]
	fn fee_rate_from_amount_and_weight() {
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(1_000), Weight::from_wu(0),
			),
			None // Divide by zero avoided
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(u64::MAX / 2), Weight::from_wu(1),
			),
			None // Overflow isn't allowed
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(0), Weight::from_wu(1_000),
			),
			Some(FeeRate::ZERO)
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(500), Weight::from_wu(250)
			),
			Some(FeeRate::from_sat_per_kwu(2_000))
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(100), Weight::from_wu(1000)
			),
			Some(FeeRate::from_sat_per_kwu(100))
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(10_000), Weight::from_wu(327)
			),
			Some(FeeRate::from_sat_per_kwu(30_582)) // 30,581.03 rounded up
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(10_000), Weight::from_wu(256)
			),
			Some(FeeRate::from_sat_per_kwu(39_063)) // 39,062.5 rounded up
		);
		assert_eq!(FeeRate::from_amount_and_weight_ceil(
				Amount::from_sat(10_000), Weight::from_wu(2_588)
			),
			Some(FeeRate::from_sat_per_kwu(3_864)) // 3,863.98 rounded up
		);
	}

	#[test]
	fn fee_rate_from_sat_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kvb_ceil(1_000),
			FeeRate::from_sat_per_kwu(250)
		);
		assert_eq!(FeeRate::from_sat_per_kvb_ceil(7_372),
			FeeRate::from_sat_per_kwu(1_843)
		);
		assert_eq!(FeeRate::from_sat_per_kvb_ceil(238),
			FeeRate::from_sat_per_kwu(60) // 59.5 rounded up
		);
		assert_eq!(FeeRate::from_sat_per_kvb_ceil(15_775),
			FeeRate::from_sat_per_kwu(3_944) // 3943.75 rounded up
		);
		assert_eq!(FeeRate::from_sat_per_kvb_ceil(10_125),
			FeeRate::from_sat_per_kwu(2_532) // 2531.25 rounded up
		);
	}

	#[test]
	fn fee_rate_from_sat_per_vb_decimal_checked() {
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(-1.0), None);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(-15_4921.0), None);

		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(1.0),
			Some(FeeRate::from_sat_per_kwu(250))
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(7.372),
			Some(FeeRate::from_sat_per_kwu(1_843))
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(0.238),
			Some(FeeRate::from_sat_per_kwu(60)) // 59.5 rounded up
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(15.775),
			Some(FeeRate::from_sat_per_kwu(3_944)) // 3943.75 rounded up
		);
		assert_eq!(FeeRate::from_sat_per_vb_decimal_checked_ceil(10.12452),
			Some(FeeRate::from_sat_per_kwu(2_532)) // 2531.13 rounded up
		);
	}

	#[test]
	fn fee_rate_to_btc_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kwu(250).to_btc_per_kvb(), "0.00001");
		assert_eq!(FeeRate::from_sat_per_kwu(1_843).to_btc_per_kvb(), "0.00007372");
		assert_eq!(FeeRate::from_sat_per_kwu(60).to_btc_per_kvb(), "0.0000024");
		assert_eq!(FeeRate::from_sat_per_kwu(3_944).to_btc_per_kvb(), "0.00015776");
		assert_eq!(FeeRate::from_sat_per_kwu(2_532).to_btc_per_kvb(), "0.00010128");
	}

	#[test]
	fn fee_rate_to_sat_per_kvb() {
		assert_eq!(FeeRate::from_sat_per_kwu(250).to_sat_per_kvb(), 1_000);
		assert_eq!(FeeRate::from_sat_per_kwu(1_843).to_sat_per_kvb(), 7_372);
		assert_eq!(FeeRate::from_sat_per_kwu(60).to_sat_per_kvb(), 240);
		assert_eq!(FeeRate::from_sat_per_kwu(3_944).to_sat_per_kvb(), 15_776);
		assert_eq!(FeeRate::from_sat_per_kwu(2_532).to_sat_per_kvb(), 10_128);
	}
}
