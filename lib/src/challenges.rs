use std::io::Write as _;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, schnorr, Message};

use crate::{OffboardRequest, SignedVtxoRequest, Vtxo, VtxoId, SECP};
use crate::encode::ProtocolEncoding;
use crate::lightning::PaymentHash;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundAttemptChallenge([u8; 32]);

impl RoundAttemptChallenge {
	const CHALENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark round input ownership proof ";

	pub fn new(value: [u8; 32]) -> Self {
		Self(value)
	}

	pub fn generate() -> Self {
		Self(rand::random())
	}

	pub fn inner(&self) -> [u8; 32] {
		self.0
	}

	/// Combines [RoundAttemptChallenge] and [VtxoId] in a signable message
	///
	/// Note: because we use [`VtxoId`] in the message, there is no
	fn as_signable_message(
		&self,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
		offboard_reqs: &[OffboardRequest],
	) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&self.0).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&vtxo_reqs.len().to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.vtxo.amount.to_sat().to_be_bytes()).unwrap();
			req.vtxo.policy.encode(&mut engine).unwrap();
			req.cosign_pubkey.encode(&mut engine).unwrap();
		}

		engine.write_all(&offboard_reqs.len().to_be_bytes()).unwrap();
		for req in offboard_reqs {
			req.to_txout().encode(&mut engine).unwrap();
		}
		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(
		&self,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
		offboard_reqs: &[OffboardRequest],
		vtxo_keypair: Keypair,
	) -> schnorr::Signature {
		let msg = self.as_signable_message(vtxo_id, vtxo_reqs, offboard_reqs);
		SECP.sign_schnorr_with_aux_rand(&msg, &vtxo_keypair, &rand::random())
	}

	pub fn verify_input_vtxo_sig(
		&self,
		vtxo: &Vtxo,
		vtxo_reqs: &[SignedVtxoRequest],
		offboard_reqs: &[OffboardRequest],
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		let msg = self.as_signable_message(vtxo.id(), vtxo_reqs, offboard_reqs);
		SECP.verify_schnorr( sig, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct LightningReceiveChallenge(PaymentHash);

impl LightningReceiveChallenge {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Lightning receive VTXO challenge";

	pub fn new(value: PaymentHash) -> Self {
		Self(value)
	}

	/// Combines [VtxoId] and the inner [PaymentHash] to prove ownership of
	/// a VTXO while commiting to the Lightning receive associated with the unique
	/// payment hash.
	fn as_signable_message(&self, vtxo_id: VtxoId) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&self.0.to_byte_array()).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(
		&self,
		vtxo_id: VtxoId,
		vtxo_keypair: Keypair,
	) -> schnorr::Signature {
		SECP.sign_schnorr_with_aux_rand(
			&LightningReceiveChallenge::as_signable_message(self, vtxo_id),
			&vtxo_keypair,
			&rand::random()
		)
	}

	pub fn verify_input_vtxo_sig(
		&self,
		vtxo: &Vtxo,
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		SECP.verify_schnorr(
			sig,
			&LightningReceiveChallenge::as_signable_message(self, vtxo.id()),
			&vtxo.user_pubkey().x_only_public_key().0,
		)
	}
}
