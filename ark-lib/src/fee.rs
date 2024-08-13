
use bitcoin::{opcodes, Amount, FeeRate, ScriptBuf, TxOut, Witness};

/// The minimum feerate for transaction relay.
///
/// Currently 1 sat/vb.
///
/// To ensure proper relay across the actual network, we might set this
/// variable to something higher than the network's policy relay feerate.
pub const RELAY_FEERATE: FeeRate = FeeRate::from_sat_per_kwu(250);

/// Dust value of 330 satoshis.
///
/// This is the dust value for p2tr and p2wsh outputs.
pub const DUST: Amount = Amount::from_sat(330);

/// The size in bytes of a dust fee anchor created with [dust_anchor].
pub const DUST_ANCHOR_SIZE: usize = 43;

/// The Script that holds only the OP_TRUE opcode.
fn op_true_script() -> ScriptBuf {
	ScriptBuf::from_bytes(vec![opcodes::OP_TRUE.to_u8()])
}

/// A p2wsh OP_TRUE fee anchor with the dust amount.
pub fn dust_anchor() -> TxOut {
	lazy_static! {
		static ref DUST_ANCHOR: TxOut = TxOut {
			script_pubkey: {
				ScriptBuf::new_p2wsh(&op_true_script().wscript_hash())
			},
			value: DUST,
		};
	}

	DUST_ANCHOR.clone()
}

/// The input witness for a dust fee anchor.
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

	#[test]
	fn test_dust_fee_anchor_size() {
		assert_eq!(DUST_ANCHOR_SIZE, bitcoin::consensus::serialize(&dust_anchor()).len());
	}
}
