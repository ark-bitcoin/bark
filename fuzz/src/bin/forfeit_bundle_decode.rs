use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::forfeit::HashLockedForfeitBundle;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<HashLockedForfeitBundle, ProtocolDecodingError> =
		HashLockedForfeitBundle::deserialize(&mut data.as_ref());

	if let Ok(bundle) = result {
		let serialized = bundle.serialize();

		let bundle2: HashLockedForfeitBundle =
			HashLockedForfeitBundle::deserialize(&mut serialized.as_slice())
				.expect("re-serialization should succeed");

		let serialized2 = bundle2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
