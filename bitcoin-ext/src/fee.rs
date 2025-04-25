
use bitcoin::{ScriptBuf, TxOut, Weight};
use cbitcoin::Amount;

use crate::bitcoin::ScriptBufExt;


/// The size in bytes of a fee anchor created with P2A script.
pub const FEE_ANCHOR_WEIGHT: Weight = Weight::from_vb_unchecked(13);

/// The witness size of a witness spending a dust anchor.
pub const FEE_ANCHOR_SPEND_WEIGHT: Weight = Weight::from_wu(1);

pub fn fee_anchor() -> TxOut {
	lazy_static! {
		static ref FEE_ANCHOR: TxOut = TxOut {
			script_pubkey: { ScriptBuf::new_p2a() },
			value: Amount::ZERO,
		};
	}

	FEE_ANCHOR.clone()
}

#[cfg(test)]
mod test {
	use cbitcoin::{absolute::Height, psbt, transaction::Version, Transaction, TxIn, Witness};

use super::*;

	#[test]
	fn test_dust_fee_anchor_size() {
		assert_eq!(
			FEE_ANCHOR_WEIGHT,
			Weight::from_vb(bitcoin::consensus::serialize(&fee_anchor()).len() as u64).unwrap(),
		);
	}

	#[test]
	fn test_fee_anchor_spend_weight() {
		let psbt_in = psbt::Input {
			witness_utxo: Some(fee_anchor()),
			final_script_witness: Some(Witness::new()),
			..Default::default()
		};

		let psbt = psbt::Psbt {
			inputs: vec![psbt_in],
			outputs: vec![],

			unsigned_tx: Transaction {
				version: Version::TWO,
				lock_time: cbitcoin::absolute::LockTime::Blocks(Height::ZERO),
				input: vec![TxIn::default()],
				output: vec![],
			},
			xpub: Default::default(),
			version: 0,
			proprietary: Default::default(),
			unknown: Default::default(),
		};

		assert_eq!(
			psbt.extract_tx().unwrap().input[0].witness.size() as u64,
			FEE_ANCHOR_SPEND_WEIGHT.to_wu(),
		);
	}
}

