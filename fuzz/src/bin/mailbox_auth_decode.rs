use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::encode::{ProtocolDecodingError, ProtocolEncoding};
use ark::mailbox::MailboxAuthorization;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("mailbox_auth_decode", data, do_test);
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
				.oracle("re-serialization should succeed");

		let serialized2 = auth2.serialize();
		bark_fuzz::oracle_assert_eq!(
			serialized, serialized2,
			"serialization should be deterministic"
		);
	}
}
