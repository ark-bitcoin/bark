use std::io::{self, Write as _};

use bitcoin::consensus::WriteExt;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::key::Keypair;
use bitcoin::secp256k1::{self, schnorr, Message};

use crate::{SignedVtxoRequest, Vtxo, VtxoId, VtxoRequest, SECP};
use crate::arkoor::ArkoorDestination;
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

/// Attestation for proving ownership of a VTXO when requesting an arkoor cosign.
///
/// Commits to the input VTXO ID and all output destinations, binding the
/// attestation to the specific transaction the user intends. One
/// attestation is created per input VTXO / part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ArkoorCosignAttestation {
	signature: schnorr::Signature,
}

impl ArkoorCosignAttestation {
	const CHALLENGE_MESSAGE_PREFIX: &'static [u8; 32] = b"arkoor cosign attestation       ";

	pub fn new(
		vtxo_id: VtxoId,
		outputs: &[&ArkoorDestination],
		vtxo_keypair: &Keypair,
	) -> Self {
		let msg = Self::compute_message(vtxo_id, outputs);
		let signature = SECP.sign_schnorr_with_aux_rand(&msg, vtxo_keypair, &rand::random());
		Self { signature }
	}

	/// Verify the attestation against a VTXO and outputs
	pub fn verify(&self, vtxo: &Vtxo, outputs: &[&ArkoorDestination]) -> Result<(), secp256k1::Error> {
		let msg = Self::compute_message(vtxo.id(), outputs);
		SECP.verify_schnorr(&self.signature, &msg, &vtxo.user_pubkey().x_only_public_key().0)
	}

	fn compute_message(vtxo_id: VtxoId, outputs: &[&ArkoorDestination]) -> Message {
		let mut eng = sha256::Hash::engine();
		eng.input(Self::CHALLENGE_MESSAGE_PREFIX);
		eng.input(&vtxo_id.to_bytes());

		eng.emit_u32(outputs.len() as u32).unwrap();
		for output in outputs {
			eng.emit_u64(output.total_amount.to_sat()).unwrap();
			output.policy.encode(&mut eng).unwrap();
		}
		Message::from_digest(sha256::Hash::from_engine(eng).to_byte_array())
	}
}

impl ProtocolEncoding for ArkoorCosignAttestation {
	fn encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.signature.encode(writer)
	}

	fn decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, ProtocolDecodingError> {
		let signature = schnorr::Signature::decode(reader)?;
		Ok(Self { signature })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::{Amount, PublicKey, ScriptBuf};
	use bitcoin::hashes::Hash;
	use bitcoin::hex::DisplayHex;
	use std::str::FromStr;
	use crate::FeeRate;
	use crate::test_util::dummy::{DummyTestVtxoSpec, DUMMY_USER_KEY};
	use crate::test_util::encoding_roundtrip;
	use crate::vtxo::policy::{PubkeyVtxoPolicy, VtxoPolicy};
	use crate::musig;

	lazy_static! {
		static ref TEST_CHALLENGE: Challenge = Challenge::new([0x42; 32]);
	}

	#[test]
	fn test_round_attempt_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let challenge = *TEST_CHALLENGE;
		let vtxo_id = vtxo.id();

		let vtxo_req = VtxoRequest {
			amount: Amount::from_sat(100_000),
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy {
				user_pubkey: DUMMY_USER_KEY.public_key(),
			}),
		};
		let (_, pub_nonce) = musig::nonce_pair(&DUMMY_USER_KEY);
		let signed_vtxo_req = SignedVtxoRequest {
			vtxo: vtxo_req,
			cosign_pubkey: DUMMY_USER_KEY.public_key(),
			nonces: vec![pub_nonce],
		};
		let vtxo_reqs = vec![signed_vtxo_req];

		let attestation = RoundAttemptAttestation::new(
			challenge,
			vtxo_id,
			&vtxo_reqs,
			&DUMMY_USER_KEY,
		);

		println!("RoundAttemptAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(challenge, &vtxo, &vtxo_reqs).expect("verification failed");

		// Hard-coded attestation test
		let vector = "ddbf11d8022ec8bcc85704e0ee0c27f1c26d024c43692653d060284ad5cf32ebf89d849b6943d7b1cb9e9c108251c23f067e95bf585fabcf4be5baab8a53897a";
		let hardcoded = RoundAttemptAttestation::deserialize_hex(&vector)
			.expect("valid attestation");
		hardcoded.verify(challenge, &vtxo, &vtxo_reqs).expect("hardcoded verification failed");
	}

	#[test]
	fn test_delegated_round_participation_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let vtxo_id = vtxo.id();

		let vtxo_req = VtxoRequest {
			amount: Amount::from_sat(100_000),
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy {
				user_pubkey: DUMMY_USER_KEY.public_key(),
			}),
		};
		let vtxo_reqs = vec![vtxo_req];

		let attestation = DelegatedRoundParticipationAttestation::new(
			vtxo_id,
			&vtxo_reqs,
			&DUMMY_USER_KEY,
		);
		println!("DelegatedRoundParticipationAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(&vtxo, &vtxo_reqs).expect("verification failed");

		// Hard-coded attestation test
		let vector = "fc482a0ef7b86427416865657986032bb49d458c3649097a389670aabee26bd7789218f18b2b58cc68524cb7ae4f224b19fcb6d905e50e63d32dacc04d78cf32";
		let hardcoded = DelegatedRoundParticipationAttestation::deserialize_hex(&vector)
			.expect("valid attestation");
		hardcoded.verify(&vtxo, &vtxo_reqs).expect("hardcoded verification failed");
	}

	#[test]
	fn test_lightning_receive_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let payment_hash = PaymentHash::from(sha256::Hash::hash(&[0x42; 32]));
		let vtxo_id = vtxo.id();

		let attestation = LightningReceiveAttestation::new(
			payment_hash,
			vtxo_id,
			&DUMMY_USER_KEY,
		);
		println!("LightningReceiveAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(payment_hash, &vtxo).expect("verification failed");

		// Hard-coded attestation test
		let vector = "a1240a572d9298c08a75102fb872b8d30bae521228083ec717f220d32de3b4446e7214e6e9e1c586c797fdff8b67e26d6f81a497dee5d584bdc80851e06c7fd5";
		let hardcoded = LightningReceiveAttestation::deserialize_hex(&vector)
			.expect("valid attestation");
		hardcoded.verify(payment_hash, &vtxo).expect("hardcoded verification failed");
	}

	#[test]
	fn test_vtxo_status_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let vtxo_id = vtxo.id();

		let attestation = VtxoStatusAttestation::new(vtxo_id, &DUMMY_USER_KEY);
		println!("VtxoStatusAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(&vtxo).expect("verification failed");

		// Hard-coded attestation test
		let vector = "ae3bb779ec3f700ccef8031f6589797ec7ac56443b01ed495bef210c8ca12a603c26ffaa2d30502a911c635b5926f1c898cad343b7cd31105aaa22c4c3688f54";
		let hardcoded = VtxoStatusAttestation::deserialize_hex(&vector)
			.expect("valid attestation");
		hardcoded.verify(&vtxo).expect("hardcoded verification failed");
	}

	#[test]
	fn test_arkoor_cosign_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let vtxo_id = vtxo.id();

		let dest = ArkoorDestination {
			total_amount: Amount::from_sat(50_000),
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy {
				user_pubkey: DUMMY_USER_KEY.public_key(),
			}),
		};
		let outputs = vec![&dest];

		let attestation = ArkoorCosignAttestation::new(
			vtxo_id,
			&outputs,
			&DUMMY_USER_KEY,
		);
		println!("ArkoorCosignAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(&vtxo, &outputs).expect("verification failed");
	}

	#[test]
	fn test_offboard_request_attestation() {
		let spec = DummyTestVtxoSpec::default();
		let (_tx, vtxo) = spec.build();

		let req_pk = PublicKey::from_str(
			"02271fba79f590251099b07fa0393b4c55d5e50cd8fca2e2822b619f8aabf93b74",
		).unwrap();
		let xonly_pk = req_pk.inner.x_only_public_key().0;
		let offboard_req = OffboardRequest {
			script_pubkey: ScriptBuf::new_p2tr(&*SECP, xonly_pk, None),
			net_amount: Amount::from_sat(50_000),
			deduct_fees_from_gross_amount: false,
			fee_rate: FeeRate::from_sat_per_vb(10).unwrap(),
		};
		let inputs = vec![vtxo.id()];

		let attestation = OffboardRequestAttestation::new(
			&offboard_req,
			&inputs,
			&DUMMY_USER_KEY,
		);
		println!("OffboardRequestAttestation hex: {}", attestation.serialize().as_hex());
		encoding_roundtrip(&attestation);
		attestation.verify(&offboard_req, &inputs, &vtxo).expect("verification failed");

		// Hard-coded attestation test
		let vector = "d6c85934b715c086164294645fadbe6a08fe6263609f38b44c23239913935c2e30fe5e9ad099941e751facb039797b6c920a90095b5e1cf26cc8aa274082aead";
		let hardcoded = OffboardRequestAttestation::deserialize_hex(&vector)
			.expect("valid attestation");
		hardcoded.verify(&offboard_req, &inputs, &vtxo).expect("hardcoded verification failed");
	}
}
