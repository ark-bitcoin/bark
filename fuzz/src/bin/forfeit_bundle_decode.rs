use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::forfeit::HashLockedForfeitBundle;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("forfeit_bundle_decode", data, do_test);
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
				.oracle("re-serialization should succeed");

		let serialized2 = bundle2.serialize();
		bark_fuzz::oracle_assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
