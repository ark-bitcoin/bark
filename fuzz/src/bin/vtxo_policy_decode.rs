use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::VtxoPolicy;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<VtxoPolicy, ProtocolDecodingError> =
		VtxoPolicy::deserialize(&mut data.as_ref());

	if let Ok(policy) = result {
		let serialized = policy.serialize();

		let policy2: VtxoPolicy =
			VtxoPolicy::deserialize(&mut serialized.as_slice())
				.expect("re-serialization should succeed");

		let serialized2 = policy2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
