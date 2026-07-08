//! Roundtrip-fuzz both policy decoders:
//! - `ServerVtxoPolicy` — the server-side policy variant.
//! - `VtxoPolicy` — the user-facing policy a client sends in `submit_payment`,
//!   `submit_round_participation`, `request_arkoor_cosign`, etc. (decoded by
//!   the `TryFrom<protos::*>` conversions in `server-rpc/src/convert.rs`).
//!
//! `data[0]` selects the type so coverage feedback can specialise on each;
//! the rest is the payload (first-byte-selector pattern, writing-fuzz-targets.md).

use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::ServerVtxoPolicy;
use ark::VtxoPolicy;
use ark::encode::ProtocolEncoding;

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("vtxo_policy_decode", data, do_test);
		});
	}
}

fn do_test(data: &[u8]) {
	if data.is_empty() {
		return;
	}
	let payload = &data[1..];
	match data[0] % 2 {
		0 => test_server_policy(payload),
		1 => test_user_policy(payload),
		_ => bark_fuzz::oracle_unreachable!(),
	}
}

fn test_server_policy(data: &[u8]) {
	let result = ServerVtxoPolicy::deserialize(&mut data.as_ref());

	if let Ok(policy) = result {
		let serialized = policy.serialize();

		let policy2 = ServerVtxoPolicy::deserialize(&mut serialized.as_slice())
			.oracle("re-serialization should succeed");
		bark_fuzz::oracle_assert_eq!(policy, policy2, "policy roundtrip should be equal");

		let serialized2 = policy2.serialize();
		bark_fuzz::oracle_assert_eq!(serialized, serialized2, "serialization should be deterministic");

		if let Some(user) = policy.into_user_policy() {
			let user_serialized = user.serialize();
			bark_fuzz::oracle_assert_eq!(serialized, user_serialized, "user serialization should be equal");
		}
	}
}

fn test_user_policy(data: &[u8]) {
	let result = VtxoPolicy::deserialize(&mut data.as_ref());

	if let Ok(policy) = result {
		let serialized = policy.serialize();

		let policy2 = VtxoPolicy::deserialize(&mut serialized.as_slice())
			.oracle("re-serialization should succeed");
		bark_fuzz::oracle_assert_eq!(policy, policy2, "policy roundtrip should be equal");

		let serialized2 = policy2.serialize();
		bark_fuzz::oracle_assert_eq!(serialized, serialized2, "serialization should be deterministic");
	}
}
