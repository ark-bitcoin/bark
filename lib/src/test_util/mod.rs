pub mod dummy;
pub mod vectors;
pub use self::vectors::VTXO_VECTORS;


use std::fmt;

use bitcoin::hex::DisplayHex;

use crate::{ProtocolEncoding, Vtxo};
use crate::vtxo::GenesisTransition;


impl Vtxo {
	pub fn invalidate_final_sig(&mut self) {
		let fake = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let item = self.genesis.last_mut().unwrap();
		match item.transition {
			GenesisTransition::Cosigned(ref mut inner) => inner.signature = fake,
			GenesisTransition::HashLockedCosigned(ref mut inner) => {
				inner.signature.replace(fake).expect("didn't have signature");
			},
			GenesisTransition::Arkoor(ref mut inner) => {
				inner.signature.replace(fake).expect("didn't have arkoor signature");
			},
		}
	}
}

/// Test that the object's encoding round-trips.
pub fn encoding_roundtrip<T>(object: &T)
where
	T: ProtocolEncoding + fmt::Debug + PartialEq,
{
	let encoded = object.serialize();
	let decoded = T::deserialize(&encoded).unwrap();

	assert_eq!(*object, decoded);

	let re_encoded = decoded.serialize();
	assert_eq!(encoded.as_hex().to_string(), re_encoded.as_hex().to_string());
}

pub fn json_roundtrip<T>(object: &T)
where
	T: fmt::Debug + PartialEq + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
	let encoded = serde_json::to_string(object).unwrap();
	let decoded: T = serde_json::from_str(&encoded).unwrap();

	assert_eq!(*object, decoded);
}

/// Verify a tx using bitcoinkernel
#[cfg(test)]
pub fn verify_tx(
	inputs: &[bitcoin::TxOut],
	input_idx: usize,
	tx: &bitcoin::Transaction,
) -> Result<(), bitcoinkernel::KernelError> {
	use bitcoinkernel as krn;
	use bitcoin::consensus::encode::serialize;

	krn::verify(
		&krn::ScriptPubkey::new(inputs[input_idx].script_pubkey.as_bytes()).unwrap(),
		Some(inputs[input_idx].value.to_sat() as i64),
		&krn::Transaction::new(&serialize(tx)).unwrap(),
		input_idx,
		Some(krn::VERIFY_ALL),
		&inputs.iter().map(|i| krn::TxOut::new(
			&krn::ScriptPubkey::new(i.script_pubkey.as_bytes()).unwrap(),
			i.value.to_sat() as i64,
		)).collect::<Vec<_>>(),
	)
}
