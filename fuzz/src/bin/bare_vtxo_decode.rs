use honggfuzz::fuzz;

use bark_fuzz::harness::OracleResultExt;

use ark::ServerVtxoPolicy;
use ark::encode::ProtocolEncoding;
use ark::vtxo::{Bare, Vtxo};

fn main() {
	loop {
		fuzz!(|data| {
			bark_fuzz::harness::guard("bare_vtxo_decode", data, do_test);
		});
	}
}

fn do_test(data: &[u8]) {
	let result = Vtxo::<Bare, ServerVtxoPolicy>::deserialize(&mut data.as_ref());

	if let Ok(vtxo) = result {
		let serialized = vtxo.serialize();

		let vtxo2 = Vtxo::<Bare, ServerVtxoPolicy>::deserialize(&mut serialized.as_slice())
			.oracle("re-serialization should succeed");
		bark_fuzz::oracle_assert_eq!(vtxo, vtxo2, "bare vtxo roundtrip should be equal");

		let serialized2 = vtxo2.serialize();
		bark_fuzz::oracle_assert_eq!(serialized, serialized2, "serialization should be deterministic");

		if let Ok(user) = vtxo.try_into_user_vtxo() {
			let user_serialized = user.serialize();
			bark_fuzz::oracle_assert_eq!(serialized, user_serialized, "user policy serialization should be equal");
		}
	}
}
