pub mod dummy;
pub mod vectors;
pub use self::vectors::VTXO_VECTORS;


use std::collections::HashMap;
use std::fmt;

use bitcoin::{absolute, transaction, OutPoint, Transaction};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::Keypair;

use crate::{musig, ProtocolEncoding, Vtxo, VtxoRequest};
use crate::tree::signed::{
	HashlockVersion, SignedVtxoTreeSpec, UnlockHash, VtxoLeafSpec, VtxoTreeSpec,
};
use crate::vtxo::{Full, GenesisTransition};


impl Vtxo<Full> {
	pub fn invalidate_final_sig(&mut self) {
		let fake: bitcoin::secp256k1::schnorr::Signature = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();
		let item = self.genesis.items.last_mut().unwrap();
		match item.transition {
			GenesisTransition::Cosigned(ref mut inner) => inner.signature = Some(fake),
			GenesisTransition::HashLockedCosigned(ref mut inner) => {
				inner.signature.replace(fake).expect("didn't have signature");
			},
			GenesisTransition::HashLockedCosigned_v0(ref mut inner) => {
				inner.signature.replace(fake).expect("didn't have signature");
			},
			GenesisTransition::Arkoor(ref mut inner) => {
				inner.signature.replace(fake).expect("didn't have arkoor signature");
			},
		}
	}
}

/// Build a fully cosigned VTXO tree with real cosign signatures, the way
/// delegated round trees are built (no per-leaf cosign keys), using the
/// given hashlock version.
///
/// Returns the signed tree and its funding tx.
pub fn build_signed_tree(
	version: HashlockVersion,
	outputs: impl IntoIterator<Item = VtxoRequest>,
	user_cosign_key: &Keypair,
	server_key: &Keypair,
	server_cosign_key: &Keypair,
	unlock_hash: UnlockHash,
) -> (SignedVtxoTreeSpec, Transaction) {
	let reqs = outputs.into_iter().map(|vtxo| VtxoLeafSpec {
		vtxo: vtxo,
		cosign_pubkey: None,
		unlock_hash: unlock_hash,
	}).collect::<Vec<_>>();

	let mut spec = VtxoTreeSpec::new(
		reqs,
		server_key.public_key(),
		101_000,
		24,
		vec![user_cosign_key.public_key(), server_cosign_key.public_key()],
	);
	spec.hashlock_version = version;

	let funding_tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![],
		output: vec![spec.funding_tx_txout()],
	};
	let utxo = OutPoint::new(funding_tx.compute_txid(), 0);
	let unsigned = spec.into_unsigned_tree(utxo);

	let nonces = |key: &Keypair| -> (Vec<_>, Vec<_>) {
		unsigned.internal_sighashes.iter()
			.map(|sh| musig::nonce_pair_with_msg(key, &sh.to_byte_array()))
			.unzip()
	};
	let (user_secs, user_pubs) = nonces(user_cosign_key);
	let (server_secs, server_pubs) = nonces(server_cosign_key);
	let agg_nonces = user_pubs.iter().zip(&server_pubs)
		.map(|(u, s)| musig::AggregatedNonce::new(&[u, s]))
		.collect::<Vec<_>>();

	let user_sigs = unsigned.cosign_tree(&agg_nonces, user_cosign_key, user_secs);
	let server_sigs = unsigned.cosign_tree(&agg_nonces, server_cosign_key, server_secs);
	let sigs = unsigned.combine_partial_signatures(
		&agg_nonces, &HashMap::new(), &[&user_sigs, &server_sigs],
	).expect("valid partial signatures");

	(unsigned.into_signed_tree(sigs), funding_tx)
}

/// Test that the object's encoding round-trips.
pub fn encoding_roundtrip<T>(object: &T)
where
	T: ProtocolEncoding + fmt::Debug + PartialEq,
{
	let encoded = object.serialize();
	let decoded = T::deserialize(&encoded).unwrap();

	assert_eq!(*object, decoded);

	let re_encoded = decoded.serialize();
	assert_eq!(encoded.as_hex().to_string(), re_encoded.as_hex().to_string());
}

pub fn json_roundtrip<T>(object: &T)
where
	T: fmt::Debug + PartialEq + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
	let encoded = serde_json::to_string(object).unwrap();
	let decoded: T = serde_json::from_str(&encoded).unwrap();

	assert_eq!(*object, decoded);
}

/// Verify a tx using bitcoinkernel
#[cfg(test)]
pub fn verify_tx(
	inputs: &[bitcoin::TxOut],
	input_idx: usize,
	tx: &bitcoin::Transaction,
) -> Result<(), bitcoinkernel::KernelError> {
	use bitcoinkernel as krn;
	use bitcoin::consensus::encode::serialize;

	let tx = krn::Transaction::new(&serialize(tx)).unwrap();
	let spent_outputs = inputs.iter().map(|i| krn::TxOut::new(
		&krn::ScriptPubkey::new(i.script_pubkey.as_bytes()).unwrap(),
		i.value.to_sat() as i64,
	)).collect::<Vec<_>>();

	krn::verify(
		&krn::ScriptPubkey::new(inputs[input_idx].script_pubkey.as_bytes()).unwrap(),
		Some(inputs[input_idx].value.to_sat() as i64),
		&tx,
		input_idx,
		Some(krn::VERIFY_ALL),
		&krn::PrecomputedTransactionData::new(&tx, &spent_outputs).unwrap(),
	)
}
