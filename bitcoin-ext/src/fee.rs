
use bitcoin::{ScriptBuf, TxOut, Weight, Witness};
use cbitcoin::Script;

use crate::P2WSH_DUST;


/// The size in bytes of a dust fee anchor created with [dust_anchor].
pub const DUST_FEE_ANCHOR_WEIGHT: Weight = Weight::from_vb_unchecked(43);

/// The witness size of a witness spending a dust anchor.
pub const DUST_FEE_ANCHOR_SPEND_WEIGHT: Weight = Weight::from_wu(3);

/// The Script that holds only the OP_TRUE opcode.
fn op_true_script() -> &'static Script {
	Script::from_bytes(&[ 0x51 ])
}

/// A p2wsh OP_TRUE fee anchor with the dust amount.
pub fn dust_anchor() -> TxOut {
	lazy_static! {
		static ref DUST_ANCHOR: TxOut = TxOut {
			script_pubkey: {
				ScriptBuf::new_p2wsh(&op_true_script().wscript_hash())
			},
			value: P2WSH_DUST,
		};
	}

	DUST_ANCHOR.clone()
}

/// The input witness for a p2wsh OP_TRUE fee anchor.
pub fn dust_anchor_witness() -> Witness {
	lazy_static! {
		static ref DUST_ANCHOR_WITNESS: Witness = {
			let mut ret = Witness::new();
			ret.push(&op_true_script()[..]);
			ret
		};
	}

	DUST_ANCHOR_WITNESS.clone()
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::opcodes;

	#[test]
	fn test_op_true_script() {
		//! because the type checked doesn't like the readable format,
		//! just a check to make sure the magic number is right
		assert_eq!(op_true_script(), &ScriptBuf::from_bytes(vec![opcodes::OP_TRUE.to_u8()]));
	}

	#[test]
	fn test_dust_fee_anchor_size() {
		assert_eq!(
			DUST_FEE_ANCHOR_WEIGHT,
			Weight::from_vb(bitcoin::consensus::serialize(&dust_anchor()).len() as u64).unwrap(),
		);
	}
}

