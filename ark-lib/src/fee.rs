
use bitcoin::{opcodes, Amount, ScriptBuf, TxOut, Witness};

/// Dust value of 330 satoshis.
///
/// This is the dust value for p2tr and p2wsh outputs.
pub const DUST: Amount = Amount::from_sat(330);

/// The size in bytes of a dust fee anchor created with [dust_anchor].
pub const DUST_ANCHOR_SIZE: usize = 43;

/// The Script that holds only the OP_TRUE opcode.
pub fn op_true_script() -> ScriptBuf {
	ScriptBuf::from_bytes(vec![opcodes::OP_TRUE.to_u8()])
}

/// A p2wsh OP_TRUE fee anchor with the dust amount.
pub fn dust_anchor() -> TxOut {
	TxOut {
		script_pubkey: {
			ScriptBuf::new_p2wsh(&op_true_script().wscript_hash())
		},
		value: DUST,
	}
}

/// The input witness for a dust fee anchor.
pub fn dust_anchor_witness() -> Witness {
	let mut ret = Witness::new();
	ret.push(&op_true_script()[..]);
	ret
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_dust_fee_anchor_size() {
		assert_eq!(DUST_ANCHOR_SIZE, bitcoin::consensus::serialize(&dust_anchor()).len());
	}
}
