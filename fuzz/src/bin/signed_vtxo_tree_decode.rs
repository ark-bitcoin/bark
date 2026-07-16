use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::tree::signed::SignedVtxoTreeSpec;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("signed_vtxo_tree_decode", data, do_test);
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
				.oracle("re-serialization should succeed");

		let serialized2 = tree2.serialize();
		bark_fuzz::oracle_assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
