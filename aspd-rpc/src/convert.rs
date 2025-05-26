
use std::convert::TryFrom;
use std::time::Duration;

use bitcoin::secp256k1::{schnorr, PublicKey};
use bitcoin::{self, Amount, FeeRate};

use ark::{musig, VtxoId};
use ark::rounds::VtxoOwnershipChallenge;
use ark::tree::signed::VtxoTreeSpec;
use ark::util::{Decodable, Encodable};

use crate::protos;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rpc conversion error: {msg}")]
pub struct ConvertError {
	msg: &'static str,
}

impl From<&'static str> for ConvertError {
	fn from(msg: &'static str) -> ConvertError {
		ConvertError { msg }
	}
}


impl From<ark::ArkInfo> for protos::ArkInfo {
	fn from(v: ark::ArkInfo) -> Self {
		protos::ArkInfo {
			network: v.network.to_string(),
			asp_pubkey: v.asp_pubkey.serialize().to_vec(),
			round_interval_secs: v.round_interval.as_secs() as u32,
			nb_round_nonces: v.nb_round_nonces as u32,
			vtxo_exit_delta: v.vtxo_exit_delta as u32,
			vtxo_expiry_delta: v.vtxo_expiry_delta as u32,
			max_vtxo_amount: v.max_vtxo_amount.map(|v| v.to_sat()),
		}
	}
}

impl TryFrom<protos::ArkInfo> for ark::ArkInfo {
	type Error = ConvertError;
	fn try_from(v: protos::ArkInfo) -> Result<Self, Self::Error> {
		Ok(ark::ArkInfo {
			network: v.network.parse().map_err(|_| "invalid network")?,
			asp_pubkey: PublicKey::from_slice(&v.asp_pubkey).map_err(|_| "invalid asp pubkey")?,
			round_interval: Duration::from_secs(v.round_interval_secs as u64),
			nb_round_nonces: v.nb_round_nonces as usize,
			vtxo_exit_delta: v.vtxo_exit_delta.try_into()
				.map_err(|_| "invalid vtxo exit delta")?,
			vtxo_expiry_delta: v.vtxo_expiry_delta.try_into()
				.map_err(|_| "invalid vtxo expiry delta")?,
			max_vtxo_amount: v.max_vtxo_amount.map(|v| Amount::from_sat(v)),
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

impl From<ark::rounds::RoundEvent> for protos::RoundEvent {
	fn from(e: ark::rounds::RoundEvent) -> Self {
		protos::RoundEvent {
			event: Some(match e {
				ark::rounds::RoundEvent::Start(ark::rounds::RoundInfo {
					round_seq, offboard_feerate,
				}) => {
					protos::round_event::Event::Start(protos::RoundStart {
						round_seq: round_seq as u64,
						offboard_feerate_sat_vkb: offboard_feerate.to_sat_per_kwu() * 4,
					})
				},
				ark::rounds::RoundEvent::Attempt(ark::rounds::RoundAttempt {
					round_seq, attempt_seq, challenge,
				}) => {
					protos::round_event::Event::Attempt(protos::RoundAttempt {
						round_seq: round_seq as u64,
						attempt_seq: attempt_seq as u64,
						vtxo_ownership_challenge: challenge.inner().to_vec(),
					})
				},
				ark::rounds::RoundEvent::VtxoProposal {
					round_seq, vtxos_spec, unsigned_round_tx, cosign_agg_nonces, connector_pubkey,
				} => {
					protos::round_event::Event::VtxoProposal(protos::VtxoProposal {
						round_seq: round_seq as u64,
						vtxos_spec: vtxos_spec.encode(),
						unsigned_round_tx: bitcoin::consensus::serialize(&unsigned_round_tx),
						vtxos_agg_nonces: cosign_agg_nonces.into_iter()
							.map(|n| n.serialize().to_vec())
							.collect(),
						connector_pubkey: connector_pubkey.serialize().to_vec(),
					})
				},
				ark::rounds::RoundEvent::RoundProposal { round_seq, cosign_sigs, forfeit_nonces } => {
					protos::round_event::Event::RoundProposal(protos::RoundProposal {
						round_seq: round_seq as u64,
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
					})
				},
				ark::rounds::RoundEvent::Finished { round_seq, signed_round_tx } => {
					protos::round_event::Event::Finished(protos::RoundFinished {
						round_seq: round_seq as u64,
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
			protos::round_event::Event::Start(m) => {
				let offboard_feerate = FeeRate::from_sat_per_kwu(m.offboard_feerate_sat_vkb / 4);
				ark::rounds::RoundEvent::Start(ark::rounds::RoundInfo {
					round_seq: m.round_seq as usize,
					offboard_feerate,
				})
			},
			protos::round_event::Event::Attempt(m) => {
				ark::rounds::RoundEvent::Attempt(ark::rounds::RoundAttempt {
					round_seq: m.round_seq as usize,
					attempt_seq: m.attempt_seq as usize,
					challenge: VtxoOwnershipChallenge::new(
						m.vtxo_ownership_challenge.try_into().map_err(|_| "invalid challenge")?
					),
				})
			},
			protos::round_event::Event::VtxoProposal(m) => {
				ark::rounds::RoundEvent::VtxoProposal {
					round_seq: m.round_seq as usize,
					unsigned_round_tx: bitcoin::consensus::deserialize(&m.unsigned_round_tx)
						.map_err(|_| "invalid unsigned_round_tx")?,
					vtxos_spec: VtxoTreeSpec::decode(&m.vtxos_spec)
						.map_err(|_| "invalid vtxos_spec")?,
					cosign_agg_nonces: m.vtxos_agg_nonces.into_iter().map(|n| {
						musig::MusigAggNonce::from_slice(&n)
							.map_err(|_| "invalid vtxos_agg_nonces")
					}).collect::<Result<_, _>>()?,
					connector_pubkey: PublicKey::from_slice(&m.connector_pubkey)
						.map_err(|_| "invaid connector pubkey")?,
				}
			},
			protos::round_event::Event::RoundProposal(m) => {
				ark::rounds::RoundEvent::RoundProposal {
					round_seq: m.round_seq as usize,
					cosign_sigs: m.vtxo_cosign_signatures.into_iter().map(|s| {
						schnorr::Signature::from_slice(&s)
							.map_err(|_| "invalid vtxo_cosign_signatures")
					}).collect::<Result<_, _>>()?,
					forfeit_nonces: m.forfeit_nonces.into_iter().map(|f| {
						let vtxo_id = VtxoId::from_slice(&f.input_vtxo_id)
							.map_err(|_| "invalid input_vtxo_id")?;
						let nonces = f.pub_nonces.into_iter().map(|n| {
							musig::MusigPubNonce::from_slice(&n)
								.map_err(|_| "invalid pub_nonces")
						}).collect::<Result<_, _>>()?;
						Ok((vtxo_id, nonces))
					}).collect::<Result<_, ConvertError>>()?,
				}
			},
			protos::round_event::Event::Finished(m) => {
				ark::rounds::RoundEvent::Finished {
					round_seq: m.round_seq as usize,
					signed_round_tx: bitcoin::consensus::deserialize(&m.signed_round_tx)
						.map_err(|_| "invalid signed_round_tx")?,
				}
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
