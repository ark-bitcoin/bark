use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::ServerVtxoPolicy;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<ServerVtxoPolicy, ProtocolDecodingError> =
		ServerVtxoPolicy::deserialize(&mut data.as_ref());

	if let Ok(policy) = result {
		let serialized = policy.serialize();

		let policy2: ServerVtxoPolicy =
			ServerVtxoPolicy::deserialize(&mut serialized.as_slice())
				.expect("re-serialization should succeed");

		let serialized2 = policy2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
