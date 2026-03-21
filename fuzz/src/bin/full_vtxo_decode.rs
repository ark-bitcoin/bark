use honggfuzz::fuzz;

use ark::ServerVtxoPolicy;
use ark::encode::ProtocolEncoding;
use ark::vtxo::{Full, Vtxo};

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&mut data.as_ref());

	if let Ok(vtxo) = result {
		let serialized = vtxo.serialize();

		let vtxo2 = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&mut serialized.as_slice())
			.expect("re-serialization should succeed");
		assert_eq!(vtxo, vtxo2, "full vtxo roundtrip should be equal");

		let serialized2 = vtxo2.serialize();
		assert_eq!(serialized, serialized2, "serialization should be deterministic");

		let _bare = vtxo.into_bare();
	}
}

