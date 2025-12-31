use std::io::Write as _;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, schnorr, Message};

use crate::{SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest, SECP};
use crate::encode::ProtocolEncoding;
use crate::lightning::PaymentHash;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoundAttemptChallenge([u8; 32]);

impl RoundAttemptChallenge {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark round input ownership proof ";

	pub fn new(value: [u8; 32]) -> Self {
		Self(value)
	}

	pub fn generate() -> Self {
		Self(rand::random())
	}

	pub fn inner(&self) -> [u8; 32] {
		self.0
	}

	/// Combines [RoundAttemptChallenge] and round submit data in a signable message
	fn as_signable_message(
		&self,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
	) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&self.0).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&vtxo_reqs.len().to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.vtxo.amount.to_sat().to_be_bytes()).unwrap();
			req.vtxo.policy.encode(&mut engine).unwrap();
			req.cosign_pubkey.encode(&mut engine).unwrap();
		}

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(
		&self,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
		vtxo_keypair: &Keypair,
	) -> schnorr::Signature {
		let msg = self.as_signable_message(vtxo_id, vtxo_reqs);
		SECP.sign_schnorr_with_aux_rand(&msg, &vtxo_keypair, &rand::random())
	}

	pub fn verify_input_vtxo_sig(
		&self,
		vtxo: &Vtxo,
		vtxo_reqs: &[SignedVtxoRequest],
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		let msg = self.as_signable_message(vtxo.id(), vtxo_reqs);
		SECP.verify_schnorr( sig, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonInteractiveRoundParticipationChallenge;

impl NonInteractiveRoundParticipationChallenge {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"hArk round join ownership proof ";

	/// Combines [NonInteractiveRoundParticipationChallenge] and
	/// round submit data in a signable message
	fn signable_message(
		vtxo_id: VtxoId,
		vtxo_reqs: &[VtxoRequest],
	) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&vtxo_reqs.len().to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.amount.to_sat().to_be_bytes()).unwrap();
			req.policy.encode(&mut engine).unwrap();
		}

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(
		vtxo_id: VtxoId,
		vtxo_reqs: &[VtxoRequest],
		vtxo_keypair: &Keypair,
	) -> schnorr::Signature {
		let msg = Self::signable_message(vtxo_id, vtxo_reqs);
		SECP.sign_schnorr_with_aux_rand(&msg, &vtxo_keypair, &rand::random())
	}

	pub fn verify_input_vtxo_sig(
		vtxo: &Vtxo,
		vtxo_reqs: &[VtxoRequest],
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		let msg = Self::signable_message(vtxo.id(), vtxo_reqs);
		SECP.verify_schnorr( sig, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}
}

/// Challenge for proving ownership of a VTXO when claiming a Lightning receive.
///
/// This challenge combines a payment hash with the input VTXO ID to create
/// a unique signature proving the user controls the input VTXO and is authorised
/// as a mitigation against liquidity denial-of-service attacks.
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
		vtxo_keypair: &Keypair,
	) -> schnorr::Signature {
		SECP.sign_schnorr_with_aux_rand(
			&Self::as_signable_message(self, vtxo_id),
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
			&Self::as_signable_message(self, vtxo.id()),
			&vtxo.user_pubkey().x_only_public_key().0,
		)
	}
}

/// Challenge for proving ownership of a VTXO when querying its status.
///
/// This is the simplest challenge - it only commits to the VTXO ID itself,
/// with no additional challenge data or context. It proves the user controls
/// the VTXO and is authorised to query its status.
///
/// No additional unique or random challenge data is necessary here.
/// We're not concerned with guarding against "replay" attacks as this challenge
/// is for informational purposes and knowledge of this proof by a third party
/// would indicate some kind of prior privacy leak for the user.
///
/// A malicious third party that can access this signed message would only be able
/// to query the status of this specific VTXO.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct VtxoStatusChallenge;

impl VtxoStatusChallenge {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark VTXO status query challenge ";

	pub fn new() -> Self {
		Self
	}

	fn as_signable_message(&self, vtxo_id: VtxoId) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}

	pub fn sign_with(
		&self,
		vtxo_id: VtxoId,
		vtxo_keypair: &Keypair,
	) -> schnorr::Signature {
		SECP.sign_schnorr_with_aux_rand(
			&Self::as_signable_message(self, vtxo_id),
			&vtxo_keypair,
			&rand::random(),
		)
	}

	pub fn verify_input_vtxo_sig(
		&self,
		vtxo: &Vtxo,
		sig: &schnorr::Signature,
	) -> Result<(), secp256k1::Error> {
		SECP.verify_schnorr(
			sig,
			&Self::as_signable_message(self, vtxo.id()),
			&vtxo.user_pubkey().x_only_public_key().0,
		)
	}
}
