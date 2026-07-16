//! Roundtrip-fuzz the `Vtxo<Full, _>` decoder for both policy parameterisations:
//! - `Vtxo<Full, ServerVtxoPolicy>` — server-side variant.
//! - `Vtxo<Full, VtxoPolicy>` — the user-facing variant clients hand back in
//!   `register_vtxos` and `post_arkoor_message` (`<Vtxo<Full>>::deserialize`).
//!
//! The two differ in how the per-genesis-transition policy field decodes, so
//! each gets its own selector slot. `data[0]` picks the variant (first-byte
//! selector, writing-fuzz-targets.md); the rest is the payload.

use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::ServerVtxoPolicy;
use ark::VtxoPolicy;
use ark::encode::ProtocolEncoding;
use ark::vtxo::{Full, Vtxo};

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("full_vtxo_decode", data, do_test);
		});
	}
}

fn do_test(data: &[u8]) {
	if data.is_empty() {
		return;
	}
	let payload = &data[1..];
	match data[0] % 2 {
		0 => test_server(payload),
		1 => test_user(payload),
		_ => bark_fuzz::oracle_unreachable!(),
	}
}

fn test_server(data: &[u8]) {
	let result = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&mut data.as_ref());

	if let Ok(vtxo) = result {
		let serialized = vtxo.serialize();

		let vtxo2 = Vtxo::<Full, ServerVtxoPolicy>::deserialize(&mut serialized.as_slice())
			.oracle("re-serialization should succeed");
		bark_fuzz::oracle_assert_eq!(vtxo, vtxo2, "full vtxo roundtrip should be equal");

		let serialized2 = vtxo2.serialize();
		bark_fuzz::oracle_assert_eq!(serialized, serialized2, "serialization should be deterministic");

		let _bare = vtxo.into_bare();
	}
}

fn test_user(data: &[u8]) {
	let result = Vtxo::<Full, VtxoPolicy>::deserialize(&mut data.as_ref());

	if let Ok(vtxo) = result {
		let serialized = vtxo.serialize();

		let vtxo2 = Vtxo::<Full, VtxoPolicy>::deserialize(&mut serialized.as_slice())
			.oracle("re-serialization should succeed");
		bark_fuzz::oracle_assert_eq!(vtxo, vtxo2, "full vtxo roundtrip should be equal");

		let serialized2 = vtxo2.serialize();
		bark_fuzz::oracle_assert_eq!(serialized, serialized2, "serialization should be deterministic");
	}
}
