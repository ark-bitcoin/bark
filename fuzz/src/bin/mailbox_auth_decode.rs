use honggfuzz::fuzz;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::mailbox::MailboxAuthorization;

fn main() {
	loop {
		fuzz!(|data| {
			do_test(data);
		});
	}
}

fn do_test(data: &[u8]) {
	let result: Result<MailboxAuthorization, ProtocolDecodingError> =
		MailboxAuthorization::deserialize(&mut data.as_ref());

	if let Ok(auth) = result {
		let serialized = auth.serialize();

		let auth2: MailboxAuthorization =
			MailboxAuthorization::deserialize(&mut serialized.as_slice())
				.expect("re-serialization should succeed");

		let serialized2 = auth2.serialize();
		assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
