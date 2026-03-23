use honggfuzz::fuzz;

use ark::ServerVtxoPolicy;
use ark::encode::ProtocolEncoding;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result = ServerVtxoPolicy::deserialize(&mut data.as_ref());

	if let Ok(policy) = result {
		let serialized = policy.serialize();

		let policy2 = ServerVtxoPolicy::deserialize(&mut serialized.as_slice())
			.expect("re-serialization should succeed");
		assert_eq!(policy, policy2, "policy roundtrip should be equal");

		let serialized2 = policy2.serialize();
		assert_eq!(serialized, serialized2, "serialization should be deterministic");

		if let Some(user) = policy.into_user_policy() {
			let user_serialized = user.serialize();
			assert_eq!(serialized, user_serialized, "user serialization should be equal");
		}
	}
}
