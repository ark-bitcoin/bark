
use std::fmt;
use std::borrow::Cow;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use chrono::{DateTime, Utc};
use lightning_invoice::Bolt11Invoice;
use postgres_types::{FromSql, ToSql};
use tokio_postgres::Row;

use ark::{Vtxo, VtxoId};
use ark::musig::{MusigPartialSignature, MusigPubNonce, MusigSecNonce};
use ark::musig::secpm::ffi::MUSIG_SECNONCE_LEN;
use ark::rounds::RoundId;
use ark::tree::signed::SignedVtxoTreeSpec;
use ark::util::Decodable;

use super::ClnNodeId;

#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: usize,
	pub connector_key: SecretKey,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&value.get::<_, &str>("id"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			signed_tree: SignedVtxoTreeSpec::decode(value.get("signed_tree"))?,
			nb_input_vtxos: usize::try_from(value.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(value.get("connector_key"))?,
		})
	}
}

/// The relevant state kept for a forfeited vtxo.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitState {
	/// The round at which the vtxo was forfeited. This is where the connector
	/// of the forfeit tx will come from.
	pub round_id: RoundId,
	#[serde(with = "serde::pub_nonces")]
	pub user_nonces: Vec<MusigPubNonce>,
	#[serde(with = "serde::part_sigs")]
	pub user_part_sigs: Vec<MusigPartialSignature>,
	#[serde(with = "serde::pub_nonces")]
	pub pub_nonces: Vec<MusigPubNonce>,
	pub sec_nonces: Vec<DangerousMusigSecNonce>,
}

#[derive(Debug)]
pub struct VtxoState {
	/// The id of the VTXO
	pub id: VtxoId,

	/// The raw vtxo encoded.
	pub vtxo: Vtxo,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent: Option<Txid>,
	/// The round id this vtxo was forfeited in, plus the forfeit tx signatures
	/// of the user, if the vtxo was forfeited.
	pub forfeit_state: Option<ForfeitState>,
	/// If this is an board vtxo, true after it has been swept.
	pub board_swept: bool,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent.is_none() && self.forfeit_state.is_none()
	}
}

impl TryFrom<Row> for VtxoState {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("id"))?;
		let vtxo = Vtxo::decode(row.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: vtxo_id,
			vtxo,
			expiry: u32::try_from(row.get::<_, i32>("expiry"))?,
			oor_spent: row
				.get::<_, Option<&[u8]>>("oor_spent")
				.map(|txid| Txid::from_slice(txid))
				.transpose()?,
			forfeit_state: row
				.get::<_, Option<&[u8]>>("forfeit_state")
				.map(|bytes| ciborium::from_reader(bytes))
				.transpose()?,
			board_swept: row.get::<_, bool>("board_swept"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct PendingSweep {
	pub txid: Txid,
	pub tx: Transaction
}

impl TryFrom<Row> for PendingSweep {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let txid = Txid::from_str(&value.get::<_, String>("txid"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), txid);

		Ok(Self { txid, tx })
	}
}

#[derive(Debug, Clone, Default)]
pub struct LightningIndexes {
	pub created_index: u64,
	pub updated_index: u64,
}

/// The status of a lightning invoice payment.
///
/// Once the aspd receives a payment request, its status is `Requested`.
/// The aspd will pass on the payment to a lightning node which changes the status to `Submitted`.
/// The lightning node payment will either fail or succeed,
/// updating the status to `Failed` or `Succeeded` respectively.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSql, FromSql, PartialEq, Eq)]
#[postgres(name = "lightning_payment_status")]
pub enum LightningPaymentStatus {
	#[postgres(name = "requested")]
	Requested,
	#[postgres(name = "submitted")]
	Submitted,
	#[postgres(name = "succeeded")]
	Succeeded,
	#[postgres(name = "failed")]
	Failed,
}

impl LightningPaymentStatus {
	pub fn is_final(&self) -> bool {
		match self {
			LightningPaymentStatus::Requested => false,
			LightningPaymentStatus::Submitted => false,
			LightningPaymentStatus::Succeeded => true,
			LightningPaymentStatus::Failed => true,
		}
	}
}

impl fmt::Display for LightningPaymentStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LightningPaymentStatus::Requested => f.write_str("requested"),
			LightningPaymentStatus::Submitted => f.write_str("submitted"),
			LightningPaymentStatus::Succeeded => f.write_str("succeeded"),
			LightningPaymentStatus::Failed => f.write_str("failed"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct LightningInvoice {
	pub lightning_invoice_id: i64,
	pub invoice: Bolt11Invoice,
	pub payment_hash: sha256::Hash,
	pub final_amount_msat: Option<u64>,
	pub preimage: Option<[u8; 32]>,
	pub last_attempt_status: Option<LightningPaymentStatus>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl TryFrom<Row> for LightningInvoice {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(LightningInvoice {
			lightning_invoice_id: row.get("lightning_invoice_id"),
			invoice: Bolt11Invoice::from_str(row.get("invoice"))
				.context("error decoding bolt11 invoice from db")?,
			payment_hash: sha256::Hash::from_slice(row.get("payment_hash"))
				.context("error decoding payment hash from db")?,
			final_amount_msat: row.get::<_, Option<i64>>("final_amount_msat").map(|i| i as u64),
			preimage: row.get::<_, Option<&[u8]>>("preimage").map(|b| {
				b.try_into().context("invalid preimage, not 32 bytes")
			}).transpose()?,
			last_attempt_status: row.get::<_, Option<LightningPaymentStatus>>("status"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct LightningPaymentAttempt {
	pub lightning_payment_attempt_id: i64,
	pub lightning_invoice_id: i64,
	pub lightning_node_id: ClnNodeId,
	pub amount_msat: u64,
	pub status: LightningPaymentStatus,
	pub error: Option<String>,
	pub created_at: DateTime<Utc>,
	pub updated_at: DateTime<Utc>,
}

impl<'a> From<&'a Row> for LightningPaymentAttempt {
	fn from(row: &'a Row) -> Self {
		LightningPaymentAttempt {
			lightning_payment_attempt_id: row.get("lightning_payment_attempt_id"),
			lightning_invoice_id: row.get("lightning_invoice_id"),
			lightning_node_id: row.get("lightning_node_id"),
			amount_msat: row.get::<_, i64>("amount_msat") as u64,
			status: row.get("status"),
			error: row.get("error"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		}
	}
}

// FORFEIT WATCHER

#[derive(Debug)]
pub struct ForfeitRoundState {
	pub round_id: RoundId,
	pub nb_input_vtxos: u32,
	pub nb_connectors_used: u32,
	pub connector_key: SecretKey,
}

impl TryFrom<Row> for ForfeitRoundState {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ForfeitRoundState {
			round_id: RoundId::from_str(&row.get::<_, &str>("id"))
				.context("bad round_id stored in forfeit state")?,
			nb_input_vtxos: row.get("nb_input_vtxos"),
			nb_connectors_used: row.get("nb_connectors_used"),
			connector_key: SecretKey::from_slice(&row.get::<_, &[u8]>("connector_key"))
				.context("bad connector key stored in forfeit state")?,
		})
	}
}

#[derive(Debug)]
pub struct ForfeitClaimState<'a> {
	pub vtxo: VtxoId,
	pub connector_tx: Option<Cow<'a, Transaction>>,
	pub connector_cpfp: Option<Cow<'a, Transaction>>,
	pub connector: OutPoint,
	pub forfeit_tx: Cow<'a, Transaction>,
	pub forfeit_cpfp: Option<Cow<'a, Transaction>>,
}

impl TryFrom<Row> for ForfeitClaimState<'static> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(ForfeitClaimState {
			vtxo: VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?,
			connector_tx: row.get::<_, Option<&[u8]>>("connector_tx")
				.map(deserialize).transpose()
				.context("invalid connector_tx")?
				.map(Cow::Owned),
			connector_cpfp: row.get::<_, Option<&[u8]>>("connector_cpfp")
				.map(deserialize).transpose()
				.context("invalid connector_cpfp")?
				.map(Cow::Owned),
			connector: deserialize(row.get::<_, &[u8]>("connector"))
				.context("invalid connector point")?,
			forfeit_tx: Cow::Owned(deserialize(row.get::<_, &[u8]>("forfeit_tx"))
				.context("invalid forfeit_tx")?),
			forfeit_cpfp: row.get::<_, Option<&[u8]>>("forfeit_cpfp")
				.map(deserialize).transpose()
				.context("invalid forfeit_cpfp")?
				.map(Cow::Owned),
		})
	}
}


/// A type that actually represents a [MusigSecNonce] but without the
/// typesystem defenses for dangerous usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousMusigSecNonce(Vec<u8>);

impl DangerousMusigSecNonce {
	pub fn new(n: MusigSecNonce) -> Self {
		DangerousMusigSecNonce(n.dangerous_into_bytes().to_vec())
	}

	pub fn to_sec_nonce(&self) -> MusigSecNonce {
		assert_eq!(self.0.len(), MUSIG_SECNONCE_LEN);
		MusigSecNonce::dangerous_from_bytes(TryFrom::try_from(&self.0[..]).expect("right size"))
	}
}

mod serde {
	use std::fmt;
	use serde::{Deserializer, Serializer};
	use crate::serde_util::Bytes;

	pub mod pub_nonces {
		use super::*;
		use serde::ser::SerializeSeq;
		use ark::musig::MusigPubNonce;

		pub fn serialize<S: Serializer>(nonces: &Vec<MusigPubNonce>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<MusigPubNonce>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<MusigPubNonce>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of public musig nonces")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(MusigPubNonce::from_slice(e.0.as_ref())
							.map_err(serde::de::Error::custom)?);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor)
		}
	}

	pub mod part_sigs {
		use super::*;
		use serde::ser::SerializeSeq;
		use ark::musig::MusigPartialSignature;

		pub fn serialize<S: Serializer>(nonces: &Vec<MusigPartialSignature>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<MusigPartialSignature>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<MusigPartialSignature>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of partial musig signatures")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(MusigPartialSignature::from_slice(e.0.as_ref())
							.map_err(serde::de::Error::custom)?);
					}
					Ok(ret)
				}
			}
			d.deserialize_seq(Visitor)
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use bitcoin::hex::FromHex;
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::rand;
	use ark::musig;
	use crate::SECP;

	#[test]
	fn forfeit_state_round_trip() {
		let key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let (secn, pubn) = musig::nonce_pair(&key);
		let part = MusigPartialSignature::from_slice(
			&Vec::<u8>::from_hex("fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843").unwrap(),
		).unwrap();

		let ffs = ForfeitState {
			round_id: RoundId::from_slice(&[0u8; 32][..]).unwrap(),
			user_nonces: vec![pubn, pubn],
			user_part_sigs: vec![part, part],
			pub_nonces: vec![pubn, pubn],
			sec_nonces: vec![DangerousMusigSecNonce::new(secn)],
		};

		let mut encoded = Vec::new();
		ciborium::into_writer(&ffs, &mut encoded).unwrap();

		let decoded = ciborium::from_reader(&encoded[..]).unwrap();
		assert_eq!(ffs, decoded);
	}
}
