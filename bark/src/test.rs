use bitcoin::{Amount, OutPoint, Txid};

use ark::{Vtxo, BoardVtxo, VtxoSpec, vtxo::VtxoSpkSpec};

fn dummy_point(vout: u32) -> OutPoint {
	let txid: Txid = "0000000000000000000000000000000000000000000000000000000000000000".parse().unwrap();
	OutPoint { txid, vout}
}

pub fn dummy_board(index: u32) -> Vtxo {
	// We are using dummy data here because most of the tests
	// don't care.
	let point = dummy_point(index);
	let pk = "024b859e37a3a4b22731c9c452b1b55e17e580fb95dac53472613390b600e1e3f0".parse().unwrap();
	let sig = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();

	Vtxo::Board(BoardVtxo {
		exit_tx_signature: sig,
		onchain_output: point,
		spec: VtxoSpec {
			user_pubkey: pk,
			asp_pubkey: pk,
			// ensure deterministic sorting
			expiry_height: 1001 + index,
			exit_delta: 40,
			spk: VtxoSpkSpec::Exit,
			amount: Amount::from_sat(500)
		},
	})
}
