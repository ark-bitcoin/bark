use std::io::{self, Write as _};

use bitcoin::consensus::WriteExt;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, schnorr, Message};

use crate::{SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest, SECP};
use crate::encode::{ProtocolEncoding, ProtocolDecodingError};
use crate::lightning::PaymentHash;
use crate::offboard::OffboardRequest;

/// Random 32-byte challenge for challenge-response protocols
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Challenge([u8; 32]);

impl Challenge {
	pub fn new(value: [u8; 32]) -> Self {
		Self(value)
	}

	pub fn generate() -> Self {
		Self(rand::random())
	}

	pub fn inner(&self) -> [u8; 32] {
		self.0
	}
}

impl AsRef<[u8]> for Challenge {
	fn as_ref(&self) -> &[u8] {
	    &self.0[..]
	}
}

/// Attestation for self-signed round participation
///
/// Contains a signature proving ownership of a VTXO for participation
/// in a specific round attempt with a given challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct RoundAttemptAttestation {
	signature: schnorr::Signature,
}

impl RoundAttemptAttestation {
	// Note: Keeping "challenge" in prefix for backward compatibility with existing signatures
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark round input ownership proof ";

	/// Create a new attestation by signing with the provided keypair
	pub fn new(
		challenge: Challenge,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
		vtxo_keypair: &Keypair,
	) -> Self {
		let msg = Self::compute_message(challenge, vtxo_id, vtxo_reqs);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Get the signature
	pub fn signature(&self) -> &schnorr::Signature {
		&self.signature
	}

	/// Verify the attestation against a VTXO
	pub fn verify(
		&self,
		challenge: Challenge,
		vtxo: &Vtxo,
		vtxo_reqs: &[SignedVtxoRequest],
	) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(challenge, vtxo.id(), vtxo_reqs);
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(
		challenge: Challenge,
		vtxo_id: VtxoId,
		vtxo_reqs: &[SignedVtxoRequest],
	) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&challenge.inner()).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&(vtxo_reqs.len() as u64).to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.vtxo.amount.to_sat().to_be_bytes()).unwrap();
			req.vtxo.policy.encode(&mut engine).unwrap();
			req.cosign_pubkey.encode(&mut engine).unwrap();
		}

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}
}

impl ProtocolEncoding for RoundAttemptAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}

/// Attestation for delegated round participation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct DelegatedRoundParticipationAttestation {
	signature: schnorr::Signature,
}

impl DelegatedRoundParticipationAttestation {
	// Note: Keeping "challenge" in prefix for backward compatibility with existing signatures
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"hArk round join ownership proof ";

	/// Create a new attestation by signing with the provided keypair
	pub fn new(
		vtxo_id: VtxoId,
		vtxo_reqs: &[VtxoRequest],
		vtxo_keypair: &Keypair,
	) -> Self {
		let msg = Self::compute_message(vtxo_id, vtxo_reqs);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Get the signature
	pub fn signature(&self) -> &schnorr::Signature {
		&self.signature
	}

	/// Verify the attestation against a VTXO
	pub fn verify(
		&self,
		vtxo: &Vtxo,
		vtxo_reqs: &[VtxoRequest],
	) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(vtxo.id(), vtxo_reqs);
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(
		vtxo_id: VtxoId,
		vtxo_reqs: &[VtxoRequest],
	) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		engine.write_all(&(vtxo_reqs.len() as u64).to_be_bytes()).unwrap();
		for req in vtxo_reqs {
			engine.write_all(&req.amount.to_sat().to_be_bytes()).unwrap();
			req.policy.encode(&mut engine).unwrap();
		}

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}
}

impl ProtocolEncoding for DelegatedRoundParticipationAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}

/// Attestation for proving ownership of a VTXO when claiming a Lightning receive.
///
/// This attestation commits to a payment hash and the input VTXO ID to create
/// a unique signature proving the user controls the input VTXO and is authorised
/// as a mitigation against liquidity denial-of-service attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct LightningReceiveAttestation {
	signature: schnorr::Signature,
}

impl LightningReceiveAttestation {
	// Note: Keeping "challenge" in prefix for backward compatibility with existing signatures
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Lightning receive VTXO challenge";

	/// Create a new attestation by signing with the provided keypair
	pub fn new(
		payment_hash: PaymentHash,
		vtxo_id: VtxoId,
		vtxo_keypair: &Keypair,
	) -> Self {
		let msg = Self::compute_message(payment_hash, vtxo_id);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Get the signature
	pub fn signature(&self) -> &schnorr::Signature {
		&self.signature
	}

	/// Verify the attestation against a VTXO
	pub fn verify(&self, payment_hash: PaymentHash, vtxo: &Vtxo) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(payment_hash, vtxo.id());
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(payment_hash: PaymentHash, vtxo_id: VtxoId) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&payment_hash.to_byte_array()).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}
}

impl ProtocolEncoding for LightningReceiveAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}

/// Attestation for proving ownership of a VTXO when querying its status.
///
/// This is the simplest attestation - it only commits to the VTXO ID itself,
/// with no additional challenge data or context. It proves the user controls
/// the VTXO and is authorised to query its status.
///
/// No additional unique or random challenge data is necessary here.
/// We're not concerned with guarding against "replay" attacks as this attestation
/// is for informational purposes and knowledge of this proof by a third party
/// would indicate some kind of prior privacy leak for the user.
///
/// A malicious third party that can access this signed message would only be able
/// to query the status of this specific VTXO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct VtxoStatusAttestation {
	signature: schnorr::Signature,
}

impl VtxoStatusAttestation {
	// Note: Keeping "challenge" in prefix for backward compatibility with existing signatures
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark VTXO status query challenge ";

	/// Create a new attestation by signing with the provided keypair
	pub fn new(vtxo_id: VtxoId, vtxo_keypair: &Keypair) -> Self {
		let msg = Self::compute_message(vtxo_id);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Get the signature
	pub fn signature(&self) -> &schnorr::Signature {
		&self.signature
	}

	/// Verify the attestation against a VTXO
	pub fn verify(&self, vtxo: &Vtxo) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(vtxo.id());
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(vtxo_id: VtxoId) -> Message {
		let mut engine = sha256::Hash::engine();
		engine.write_all(Self::CHALLENGE_MESSAGE_PREFIX).unwrap();
		engine.write_all(&vtxo_id.to_bytes()).unwrap();

		let hash = sha256::Hash::from_engine(engine).to_byte_array();
		Message::from_digest(hash)
	}
}

impl ProtocolEncoding for VtxoStatusAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}

/// Attestation for proving ownership of a VTXO when requesting an offboard
///
/// It commits to the offboard request and all input vtxos.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct OffboardRequestAttestation {
	signature: schnorr::Signature,
}

impl OffboardRequestAttestation {
	// Note: Keeping "challenge" in prefix for backward compatibility with existing signatures
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"Ark offboard request challenge  ";

	/// Create a new attestation by signing with the provided keypair
	pub fn new(
		req: &OffboardRequest,
		inputs: &[VtxoId],
		vtxo_keypair: &Keypair,
	) -> Self {
		let msg = Self::compute_message(req, inputs);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Get the signature
	pub fn signature(&self) -> &schnorr::Signature {
		&self.signature
	}

	/// Verify the attestation against a VTXO
	pub fn verify(
		&self,
		req: &OffboardRequest,
		inputs: &[VtxoId],
		vtxo: &Vtxo,
	) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(req, inputs);
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(req: &OffboardRequest, inputs: &[VtxoId]) -> Message {
		let mut eng = sha256::Hash::engine();
		eng.input(Self::CHALLENGE_MESSAGE_PREFIX);
		req.to_txout().encode(&mut eng).unwrap();
		eng.emit_u32(inputs.len() as u32).unwrap();
		for vtxo in inputs {
			eng.input(&vtxo.to_bytes());
		}
		Message::from_digest(sha256::Hash::from_engine(eng).to_byte_array())
	}
}

impl ProtocolEncoding for OffboardRequestAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}
