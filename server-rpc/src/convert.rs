
use std::convert::TryFrom;
use std::time::Duration;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{self, Amount, FeeRate, OutPoint, Transaction};

use ark::{musig, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::arkoor::{ArkoorBuilder, ArkoorCosignResponse};
use ark::board::BoardCosignResponse;
use ark::challenges::RoundAttemptChallenge;
use ark::lightning::{PaymentHash, Preimage};
use ark::rounds::RoundId;
use ark::tree::signed::VtxoTreeSpec;

use crate::protos;


#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rpc conversion error: {msg}")]
pub struct ConvertError {
	pub msg: &'static str,
}

impl From<&'static str> for ConvertError {
	fn from(msg: &'static str) -> ConvertError {
		ConvertError { msg }
	}
}

impl From<ConvertError> for tonic::Status {
	fn from(e: ConvertError) -> Self {
		tonic::Status::invalid_argument(e.msg)
	}
}

/// Trait to convert some types from byte slices.
pub trait TryFromBytes: Sized {
	fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError>;
}

macro_rules! impl_try_from_byte_array {
	($ty:path, $exp:expr) => {
		impl TryFromBytes for $ty {
			fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError> {
				#[allow(unused)]
				use bitcoin::hashes::Hash;

				let array = TryFrom::try_from(b.as_ref())
					.map_err(|_| concat!("invalid ", $exp))?;
				Ok(<$ty>::from_byte_array(array))
			}
		}
	};
}
impl_try_from_byte_array!(PaymentHash, "lightning payment hash");
impl_try_from_byte_array!(Preimage, "lightning payment preimage");
impl_try_from_byte_array!(sha256::Hash, "SHA-256 hash");

macro_rules! impl_try_from_byte_array_result {
	($ty:path, $exp:expr) => {
		impl TryFromBytes for $ty {
			fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError> {
				Ok(TryFrom::try_from(b.as_ref()).ok()
					.and_then(|b| <$ty>::from_byte_array(b).ok())
					.ok_or(concat!("invalid ", $exp))?)
			}
		}
	};
}
impl_try_from_byte_array_result!(musig::PublicNonce, "public musig nonce");
impl_try_from_byte_array_result!(musig::PartialSignature, "partial musig signature");
impl_try_from_byte_array_result!(musig::AggregatedNonce, "aggregated musig nonce");

macro_rules! impl_try_from_byte_slice {
	($ty:path, $exp:expr) => {
		impl TryFromBytes for $ty {
			fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError> {
				#[allow(unused)] // used for the impls of hash types
				use bitcoin::hashes::Hash;

				Ok(<$ty>::from_slice(b.as_ref()).map_err(|_| concat!("invalid ", $exp))?)
			}
		}
	};
}
impl_try_from_byte_slice!(PublicKey, "public key");
impl_try_from_byte_slice!(schnorr::Signature, "Schnorr signature");
impl_try_from_byte_slice!(VtxoId, "VTXO ID");
impl_try_from_byte_slice!(RoundId, "VTXO ID");

macro_rules! impl_try_from_bytes_protocol {
	($ty:path, $exp:expr) => {
		impl TryFromBytes for $ty {
			fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError> {
				Ok(ProtocolEncoding::deserialize(b.as_ref())
					.map_err(|_| concat!("invalid ", $exp))?)
			}
		}
	};
}
impl_try_from_bytes_protocol!(OutPoint, "outpoint");
impl_try_from_bytes_protocol!(Vtxo, "VTXO");
impl_try_from_bytes_protocol!(VtxoPolicy, "VTXO policy");

macro_rules! impl_try_from_bytes_bitcoin {
	($ty:path, $exp:expr) => {
		impl TryFromBytes for $ty {
			fn from_bytes<T: AsRef<[u8]>>(b: T) -> Result<Self, ConvertError> {
				Ok(bitcoin::consensus::encode::deserialize(b.as_ref())
					.map_err(|_| concat!("invalid ", $exp))?)
			}
		}
	};
}
impl_try_from_bytes_bitcoin!(Transaction, "bitcoin transaction");


impl From<ark::ArkInfo> for protos::ArkInfo {
	fn from(v: ark::ArkInfo) -> Self {
		protos::ArkInfo {
			network: v.network.to_string(),
			server_pubkey: v.server_pubkey.serialize().to_vec(),
			round_interval_secs: v.round_interval.as_secs() as u32,
			nb_round_nonces: v.nb_round_nonces as u32,
			vtxo_exit_delta: v.vtxo_exit_delta as u32,
			vtxo_expiry_delta: v.vtxo_expiry_delta as u32,
			htlc_send_expiry_delta: v.htlc_send_expiry_delta as u32,
			htlc_expiry_delta: v.htlc_expiry_delta as u32,
			max_vtxo_amount: v.max_vtxo_amount.map(|v| v.to_sat()),
			// TODO: Remove this once we hit 0.1.0-beta.6 or higher
			// bark version 0.1.0-beta.4 and older
			// expect the max_arkoor_depth field to be set.
			//
			// To make sure they don't complain or crash when receiving
			// a bad ArkInfo message we keep pretending the field exists
			// and give them a sufficiently high value.
			#[allow(deprecated)]
			max_arkoor_depth: u16::MAX as u32,
			required_board_confirmations: v.required_board_confirmations as u32,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta as u32,
			min_board_amount: v.min_board_amount.to_sat(),
			offboard_feerate_sat_vkb: v.offboard_feerate.to_sat_per_kwu() * 4,
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
		}
	}
}

impl TryFrom<protos::ArkInfo> for ark::ArkInfo {
	type Error = ConvertError;
	fn try_from(v: protos::ArkInfo) -> Result<Self, Self::Error> {
		Ok(ark::ArkInfo {
			network: v.network.parse().map_err(|_| "invalid network")?,
			server_pubkey: PublicKey::from_slice(&v.server_pubkey)
				.map_err(|_| "invalid server pubkey")?,
			round_interval: Duration::from_secs(v.round_interval_secs as u64),
			nb_round_nonces: v.nb_round_nonces as usize,
			vtxo_exit_delta: v.vtxo_exit_delta.try_into()
				.map_err(|_| "invalid vtxo exit delta")?,
			vtxo_expiry_delta: v.vtxo_expiry_delta.try_into()
				.map_err(|_| "invalid vtxo expiry delta")?,
			htlc_send_expiry_delta: v.htlc_send_expiry_delta.try_into()
				.map_err(|_| "invalid htlc send expiry delta")?,
			htlc_expiry_delta: v.htlc_expiry_delta.try_into()
				.map_err(|_| "invalid htlc expiry delta")?,
			max_vtxo_amount: v.max_vtxo_amount.map(|v| Amount::from_sat(v)),
			required_board_confirmations: v.required_board_confirmations as usize,
			max_user_invoice_cltv_delta: v.max_user_invoice_cltv_delta.try_into()
				.map_err(|_| "invalid max user invoice cltv delta")?,
			min_board_amount: Amount::from_sat(v.min_board_amount),
			offboard_feerate: FeeRate::from_sat_per_kwu(v.offboard_feerate_sat_vkb / 4),
			ln_receive_anti_dos_required: v.ln_receive_anti_dos_required,
		})
	}
}

impl From<ark::lightning::PaymentStatus> for protos::PaymentStatus {
	fn from(value: ark::lightning::PaymentStatus) -> Self {
		match value {
			ark::lightning::PaymentStatus::Complete => protos::PaymentStatus::Complete,
			ark::lightning::PaymentStatus::Pending => protos::PaymentStatus::Pending,
			ark::lightning::PaymentStatus::Failed => protos::PaymentStatus::Failed,
		}
	}
}

impl<'a> From<&'a ark::rounds::RoundEvent> for protos::RoundEvent {
	fn from(e: &'a ark::rounds::RoundEvent) -> Self {
		protos::RoundEvent {
			event: Some(match e {
				ark::rounds::RoundEvent::Attempt(ark::rounds::RoundAttempt {
					round_seq, attempt_seq, challenge,
				}) => {
					protos::round_event::Event::Attempt(protos::RoundAttempt {
						round_seq: (*round_seq).into(),
						attempt_seq: *attempt_seq as u64,
						round_attempt_challenge: challenge.inner().to_vec(),
					})
				},
				ark::rounds::RoundEvent::VtxoProposal(ark::rounds::VtxoProposal {
					round_seq, attempt_seq, vtxos_spec, unsigned_round_tx, cosign_agg_nonces,
				}) => {
					protos::round_event::Event::VtxoProposal(protos::VtxoProposal {
						round_seq: (*round_seq).into(),
						attempt_seq: *attempt_seq as u64,
						vtxos_spec: vtxos_spec.serialize(),
						unsigned_round_tx: bitcoin::consensus::serialize(&unsigned_round_tx),
						vtxos_agg_nonces: cosign_agg_nonces.into_iter()
							.map(|n| n.serialize().to_vec())
							.collect(),
					})
				},
				ark::rounds::RoundEvent::RoundProposal(ark::rounds::RoundProposal {
					round_seq, attempt_seq, cosign_sigs, forfeit_nonces, connector_pubkey,
				}) => {
					protos::round_event::Event::RoundProposal(protos::RoundProposal {
						round_seq: (*round_seq).into(),
						attempt_seq: *attempt_seq as u64,
						vtxo_cosign_signatures: cosign_sigs.into_iter()
							.map(|s| s.serialize().to_vec()).collect(),
						forfeit_nonces: forfeit_nonces.into_iter().map(|(id, nonces)| {
							protos::ForfeitNonces {
								input_vtxo_id: id.to_bytes().to_vec(),
								pub_nonces: nonces.into_iter()
									.map(|n| n.serialize().to_vec())
									.collect(),
							}
						}).collect(),
						connector_pubkey: connector_pubkey.serialize().to_vec(),
					})
				},
				ark::rounds::RoundEvent::Finished(ark::rounds::RoundFinished {
					round_seq, attempt_seq, signed_round_tx,
				}) => {
					protos::round_event::Event::Finished(protos::RoundFinished {
						round_seq: (*round_seq).into(),
						attempt_seq: *attempt_seq as u64,
						signed_round_tx: bitcoin::consensus::serialize(&signed_round_tx),
					})
				},
			})
		}
	}
}

impl TryFrom<protos::RoundEvent> for ark::rounds::RoundEvent {
	type Error = ConvertError;

	fn try_from(m: protos::RoundEvent) -> Result<ark::rounds::RoundEvent, Self::Error> {
		Ok(match m.event.unwrap() {
			protos::round_event::Event::Attempt(m) => {
				ark::rounds::RoundEvent::Attempt(ark::rounds::RoundAttempt {
					round_seq: m.round_seq.into(),
					attempt_seq: m.attempt_seq as usize,
					challenge: RoundAttemptChallenge::new(
						m.round_attempt_challenge.try_into().map_err(|_| "invalid challenge")?
					),
				})
			},
			protos::round_event::Event::VtxoProposal(m) => {
				ark::rounds::RoundEvent::VtxoProposal(ark::rounds::VtxoProposal {
					round_seq: m.round_seq.into(),
					attempt_seq: m.attempt_seq as usize,
					unsigned_round_tx: bitcoin::consensus::deserialize(&m.unsigned_round_tx)
						.map_err(|_| "invalid unsigned_round_tx")?,
					vtxos_spec: VtxoTreeSpec::deserialize(&m.vtxos_spec)
						.map_err(|_| "invalid vtxos_spec")?,
					cosign_agg_nonces: m.vtxos_agg_nonces.into_iter().map(|n| {
						musig::AggregatedNonce::from_bytes(&n)
					}).collect::<Result<_, _>>()?,
				})
			},
			protos::round_event::Event::RoundProposal(m) => {
				ark::rounds::RoundEvent::RoundProposal(ark::rounds::RoundProposal {
					round_seq: m.round_seq.into(),
					attempt_seq: m.attempt_seq as usize,
					cosign_sigs: m.vtxo_cosign_signatures.into_iter().map(|s| {
						schnorr::Signature::from_slice(&s)
							.map_err(|_| "invalid vtxo_cosign_signatures")
					}).collect::<Result<_, _>>()?,
					forfeit_nonces: m.forfeit_nonces.into_iter().map(|f| {
						let vtxo_id = VtxoId::from_slice(&f.input_vtxo_id)
							.map_err(|_| "invalid input_vtxo_id")?;
						let nonces = f.pub_nonces.into_iter().map(|n| {
							musig::PublicNonce::from_bytes(&n)
						}).collect::<Result<_, _>>()?;
						Ok((vtxo_id, nonces))
					}).collect::<Result<_, ConvertError>>()?,
					connector_pubkey: PublicKey::from_slice(&m.connector_pubkey)
						.map_err(|_| "invalid connector pubkey")?,
				})
			},
			protos::round_event::Event::Finished(m) => {
				ark::rounds::RoundEvent::Finished(ark::rounds::RoundFinished {
					round_seq: m.round_seq.into(),
					attempt_seq: m.attempt_seq as usize,
					signed_round_tx: bitcoin::consensus::deserialize(&m.signed_round_tx)
						.map_err(|_| "invalid signed_round_tx")?,
				})
			},
		})
	}
}

impl From<crate::WalletStatus> for protos::WalletStatus {
	fn from(s: crate::WalletStatus) -> Self {
		protos::WalletStatus {
			address: s.address.assume_checked().to_string(),
			total_balance: s.total_balance.to_sat(),
			trusted_pending_balance: s.trusted_pending_balance.to_sat(),
			untrusted_pending_balance: s.untrusted_pending_balance.to_sat(),
			confirmed_balance: s.confirmed_balance.to_sat(),
			confirmed_utxos: s.confirmed_utxos.iter().map(|u| u.to_string()).collect(),
			unconfirmed_utxos: s.unconfirmed_utxos.iter().map(|u| u.to_string()).collect(),
		}
	}
}

impl TryFrom<protos::WalletStatus> for crate::WalletStatus {
	type Error = ConvertError;
	fn try_from(s: protos::WalletStatus) -> Result<Self, Self::Error> {
		Ok(crate::WalletStatus {
			address: s.address.parse().map_err(|_| "invalid address")?,
			total_balance: Amount::from_sat(s.total_balance),
			trusted_pending_balance: Amount::from_sat(s.trusted_pending_balance),
			untrusted_pending_balance: Amount::from_sat(s.untrusted_pending_balance),
			confirmed_balance: Amount::from_sat(s.confirmed_balance),
			confirmed_utxos: s.confirmed_utxos.iter().map(|u| {
				u.parse().map_err(|_| "invalid outpoint")
			}).collect::<Result<_, _>>()?,
			unconfirmed_utxos: s.unconfirmed_utxos.iter().map(|u| {
				u.parse().map_err(|_| "invalid outpoint")
			}).collect::<Result<_, _>>()?,
		})
	}
}


impl<'a> From<&'a VtxoRequest> for protos::VtxoRequest {
	fn from(v: &'a VtxoRequest) -> Self {
		protos::VtxoRequest {
			amount: v.amount.to_sat(),
			policy: v.policy.serialize(),
		}
	}
}

impl TryFrom<protos::VtxoRequest> for VtxoRequest {
	type Error = ConvertError;
	fn try_from(v: protos::VtxoRequest) -> Result<Self, Self::Error> {
		Ok(Self {
			amount: Amount::from_sat(v.amount),
			policy: VtxoPolicy::deserialize(&v.policy).map_err(|_| "invalid policy")?,
		})
	}
}

impl From<ArkoorCosignResponse> for protos::ArkoorCosignResponse {
	fn from(v: ArkoorCosignResponse) -> Self {
		Self {
			pub_nonce: v.pub_nonce.serialize().to_vec(),
			partial_sig: v.partial_signature.serialize().to_vec(),
		}
	}
}

impl TryFrom<protos::ArkoorCosignResponse> for ArkoorCosignResponse {
	type Error = ConvertError;
	fn try_from(v: protos::ArkoorCosignResponse) -> Result<Self, Self::Error> {
		Ok(Self {
			pub_nonce: musig::PublicNonce::from_bytes(&v.pub_nonce)?,
			partial_signature: musig::PartialSignature::from_bytes(&v.partial_sig)?,
		})
	}
}

impl From<Vec<ArkoorCosignResponse>> for protos::ArkoorPackageCosignResponse {
	fn from(v: Vec<ArkoorCosignResponse>) -> Self {
		Self {
			sigs: v.into_iter().map(|i| i.into()).collect(),
		}
	}
}

impl<'a> From<&'a ArkoorBuilder<'_, VtxoRequest>> for protos::ArkoorCosignRequest {
	fn from(v: &'a ArkoorBuilder<'_, VtxoRequest>) -> Self {
		Self {
			input_id: v.input.id().to_bytes().to_vec(),
			outputs: v.outputs.iter().map(|o| o.into()).collect(),
			pub_nonce: v.user_nonce.serialize().to_vec(),
		}
	}
}

impl TryFrom<protos::ArkoorPackageCosignResponse> for Vec<ArkoorCosignResponse> {
	type Error = ConvertError;
	fn try_from(v: protos::ArkoorPackageCosignResponse) -> Result<Self, Self::Error> {
		Ok(v.sigs.into_iter().map(|i| i.try_into()).collect::<Result<_, _>>()?)
	}
}

impl From<BoardCosignResponse> for protos::BoardCosignResponse {
	fn from(v: BoardCosignResponse) -> Self {
		Self {
			pub_nonce: v.pub_nonce.serialize().to_vec(),
			partial_sig: v.partial_signature.serialize().to_vec(),
		}
	}
}

impl TryFrom<protos::BoardCosignResponse> for BoardCosignResponse {
	type Error = ConvertError;
	fn try_from(v: protos::BoardCosignResponse) -> Result<Self, Self::Error> {
		Ok(Self {
			pub_nonce: musig::PublicNonce::from_bytes(&v.pub_nonce)?,
			partial_signature: musig::PartialSignature::from_bytes(&v.partial_sig)?,
		})
	}
}

impl From<ark::integration::TokenType> for protos::intman::TokenType {
	fn from(value: ark::integration::TokenType) -> Self {
		match value {
			ark::integration::TokenType::SingleUseBoard => protos::intman::TokenType::SingleUseBoard,
		}
	}
}

impl From<protos::intman::TokenType> for ark::integration::TokenType {
	fn from(value: protos::intman::TokenType) -> Self {
		match value {
			protos::intman::TokenType::SingleUseBoard => ark::integration::TokenType::SingleUseBoard,
		}
	}
}

impl From<protos::intman::TokenStatus> for ark::integration::TokenStatus {
	fn from(value: protos::intman::TokenStatus) -> Self {
		match value {
			protos::intman::TokenStatus::Unused => ark::integration::TokenStatus::Unused,
			protos::intman::TokenStatus::Used => ark::integration::TokenStatus::Used,
			protos::intman::TokenStatus::Abused => ark::integration::TokenStatus::Abused,
			protos::intman::TokenStatus::Disabled => ark::integration::TokenStatus::Disabled,
			// Setting to `Unused` since this status is an alias for `Unused` + expired.
			protos::intman::TokenStatus::Expired => ark::integration::TokenStatus::Unused,
		}
	}
}

impl From<ark::integration::TokenStatus> for protos::intman::TokenStatus {
	fn from(value: ark::integration::TokenStatus) -> Self {
		match value {
			ark::integration::TokenStatus::Unused => protos::intman::TokenStatus::Unused,
			ark::integration::TokenStatus::Used => protos::intman::TokenStatus::Used,
			ark::integration::TokenStatus::Abused => protos::intman::TokenStatus::Abused,
			ark::integration::TokenStatus::Disabled => protos::intman::TokenStatus::Disabled,
		}
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use bitcoin::hex::FromHex;
	use super::*;

	#[test]
	fn test_preimage_bytes() {
		let h = "ef2cb05d04819ddb2b9d960c7e0e295ea48ffb429712dc8f30aa48dfcc20c97e";
		let b = Vec::<u8>::from_hex(h).unwrap();

		let preimage = Preimage::from_str(h).unwrap();
		assert_eq!(preimage, Preimage::from_bytes(&b).unwrap());
		assert_eq!(preimage, Preimage::from_slice(&b).unwrap());
		assert_eq!(preimage, Preimage::from_slice(&preimage.to_vec()).unwrap());
		assert_eq!(preimage, Preimage::from_bytes(&preimage.to_vec()).unwrap());
	}
}
