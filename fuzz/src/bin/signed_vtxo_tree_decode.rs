use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::tree::signed::SignedVtxoTreeSpec;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<SignedVtxoTreeSpec, ProtocolDecodingError> =
		SignedVtxoTreeSpec::deserialize(&mut data.as_ref());

	if let Ok(tree) = result {
		let serialized = tree.serialize();

		let tree2: SignedVtxoTreeSpec =
			SignedVtxoTreeSpec::deserialize(&mut serialized.as_slice())
				.expect("re-serialization should succeed");

		let serialized2 = tree2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
