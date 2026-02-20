use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::Vtxo;
use ark::ServerVtxoPolicy;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<Vtxo<ServerVtxoPolicy>, ProtocolDecodingError> = Vtxo::deserialize(&mut data.as_ref());

	if let Ok(vtxo) = result {
		let serialized = vtxo.serialize();

		let vtxo2: Vtxo<ServerVtxoPolicy> =
			Vtxo::deserialize(&mut serialized.as_slice()).expect("re-serialization should succeed");

		let serialized2 = vtxo2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}

