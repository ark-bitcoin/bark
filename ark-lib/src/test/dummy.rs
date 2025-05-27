/// For many tests it is useful to create some VTXOs.
///
/// In many cases, these VTXOs don't need to be consensus valid
/// and it doesn't matter if any of the signatures are valid.
///
/// Constructing these VTXOs manually can be cumbersome. This module
/// creates some utilities that should allow you to quickly generate
/// some dummy VTXOs.
///
/// The module is only available if the test-util feature is used.
///
use bitcoin::{Amount, OutPoint, Txid};
use bitcoin::secp256k1::{schnorr, PublicKey, SecretKey};
use bitcoin_ext::BlockHeight;

use crate::{BoardVtxo, VtxoSpec, Vtxo, vtxo::VtxoSpkSpec};

/// Returns a dummy signature
pub fn dummy_signature() -> schnorr::Signature {
	"cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap()
}

/// Returns a dummy outpoint.
/// You can use the index to make the outpoints unique
pub fn dummy_outpoint(idx: u32) -> OutPoint {
	let txid = "0000000000000000000000000000000000000000000000000000000000000000"
		.parse::<Txid>()
		.expect("Valid transaction id");
	OutPoint::new(txid, idx)
}

pub fn dummy_asp_pubkey() -> PublicKey {
	// I have generated this key locally and it has no special meaning.
	// The asp_pubkey and asp_privkey do correspond
	"03bdd5764274d63a35b58ec22c10b5ceb211a5beb6e4903c54e492e47c0bd5e739".parse().unwrap()
}

pub fn dummy_asp_privkey() -> SecretKey {
	"8cd07e251eaf4f79b670690b251ca11e9fb1c4a0dde4b3c94d5ccfe925872384".parse().unwrap()
}

pub fn dummy_user_pubkey() -> PublicKey {
	// I have genrated this key locally and it has no special meaning.
	// the user_pubkey and user_privkey do correspond
	"02b96ae93b5254fb7a438e98c64c8f4f5fcb932b3ee2f516afba62567e443cbf9e".parse().unwrap()
}

pub fn dummy_user_privkey() -> SecretKey {
	"b651ac78f5daa479c7d0c4ec4dc997d5c830782a9a7605a7a6868395fcd46bb1".parse().unwrap()
}

pub struct DummyVtxoBuilder {
	vtxo: BoardVtxo,
}

impl DummyVtxoBuilder {
	pub fn new(idx: u32) -> Self {
		Self {
			vtxo: BoardVtxo {
				spec: VtxoSpec {
					user_pubkey: dummy_user_pubkey(),
					asp_pubkey: dummy_asp_pubkey(),
					expiry_height: 12345,
					exit_delta: 48,
					spk: VtxoSpkSpec::Exit,
					amount: Amount::from_sat(10_000),
				},
				onchain_output: dummy_outpoint(idx),
				exit_tx_signature: dummy_signature(),
			}
		}
	}

	pub fn build(self) -> Vtxo {
		Vtxo::Board(self.vtxo)
	}

	pub fn user_pubkey(mut self, user_pubkey: PublicKey) -> Self {
		self.vtxo.spec.user_pubkey = user_pubkey;
		self
	}

	pub fn asp_pubkey(mut self, asp_pubkey: PublicKey) -> Self {
		self.vtxo.spec.asp_pubkey = asp_pubkey;
		self
	}

	pub fn expiry_height(mut self, expiry_height: BlockHeight) -> Self {
		self.vtxo.spec.expiry_height = expiry_height;
		self
	}

	pub fn spk(mut self, spk: VtxoSpkSpec) -> Self {
		self.vtxo.spec.spk = spk;
		self
	}

	pub fn amount(mut self, amount: Amount) -> Self {
		self.vtxo.spec.amount = amount;
		self
	}

	pub fn onchain_output(mut self, onchain_output: OutPoint) -> Self {
		self.vtxo.onchain_output = onchain_output;
		self
	}

	pub fn exit_tx_signature(mut self, exit_tx_signature: schnorr::Signature) -> Self {
		self.vtxo.exit_tx_signature = exit_tx_signature;
		self
	}
}

