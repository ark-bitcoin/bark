
use std::borrow::Borrow;
use std::collections::BTreeMap;

use cbitcoin::taproot::ControlBlock;
use cbitcoin::{taproot, Amount, Denomination, FeeRate, OutPoint, ScriptBuf, Transaction, Weight};
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
	/// Check if this tx has a dust fee anchor output and return the outpoint of it.
	fn fee_anchor(&self) -> Option<OutPoint> {
		for (i, out) in self.borrow().output.iter().enumerate() {
			if *out == fee::dust_anchor() {
				return Some(OutPoint::new(self.borrow().compute_txid(), i as u32));
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

	fn from_msat(value: u64) -> Amount {
		Amount::from_sat(value.div_euclid(1_000))
	}
}
impl AmountExt for Amount {}


/// Extension trait for [FeeRate].
pub trait FeeRateExt: Borrow<FeeRate> {
	fn to_btc_per_kvb(&self) -> String {
		(*self.borrow() * Weight::from_vb(1000).unwrap()).to_string_in(Denomination::Bitcoin)
	}
}
impl FeeRateExt for FeeRate {}

