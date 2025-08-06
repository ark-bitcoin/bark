use std::fmt::{self, Display};
use std::borrow::Cow;
use anyhow::Context;
use bitcoin_ext::BlockHeight;
use postgres_types::{FromSql, ToSql};
use std::str::FromStr;

use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::SecretKey;
use chrono::{DateTime, Local};
use lightning_invoice::Bolt11Invoice;
use tokio_postgres::Row;

use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::musig::{PartialSignature, PublicNonce, SecretNonce};
use ark::musig::secpm::ffi::MUSIG_SECNONCE_SIZE;
use ark::rounds::RoundId;
use ark::tree::signed::SignedVtxoTreeSpec;

use super::ClnNodeId;

#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: usize,
	pub connector_key: SecretKey,
	pub expiry_height: BlockHeight,
}

impl TryFrom<Row> for StoredRound {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let id = RoundId::from_str(&value.get::<_, &str>("id"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), id.as_round_txid());

		Ok(Self {
			id, tx,
			signed_tree: SignedVtxoTreeSpec::deserialize(value.get("signed_tree"))?,
			nb_input_vtxos: usize::try_from(value.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(value.get("connector_key"))?,
			expiry_height: value.get::<_, i32>("expiry") as BlockHeight,
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
	pub user_nonces: Vec<PublicNonce>,
	#[serde(with = "serde::part_sigs")]
	pub user_part_sigs: Vec<PartialSignature>,
	#[serde(with = "serde::pub_nonces")]
	pub pub_nonces: Vec<PublicNonce>,
	pub sec_nonces: Vec<DangerousSecretNonce>,
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
	/// The round id this vtxo was forfeited in.
	pub forfeit_round_id: Option<RoundId>,
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
		let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
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
				.map(|bytes| rmp_serde::from_slice(bytes))
				.transpose()?,
			forfeit_round_id: row.get::<_, Option<&str>>("forfeit_round_id")
				.map(|id| RoundId::from_str(id))
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
/// Once the server receives a payment request, its status is `Requested`.
/// The server will pass on the payment to a lightning node which changes the status to `Submitted`.
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
	pub invoice: Invoice,
	pub payment_hash: PaymentHash,
	pub final_amount_msat: Option<u64>,
	pub preimage: Option<Preimage>,
	pub last_attempt_status: Option<LightningPaymentStatus>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl TryFrom<Row> for LightningInvoice {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(LightningInvoice {
			lightning_invoice_id: row.get("lightning_invoice_id"),
			invoice: Invoice::from_str(row.get("invoice"))
				.context("error decoding invoice from db")?,
			payment_hash: PaymentHash::try_from(row.get::<_, &[u8]>("payment_hash"))
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
	pub is_self_payment: bool,
	pub error: Option<String>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl From<Row> for LightningPaymentAttempt {
	fn from(row: Row) -> Self {
		LightningPaymentAttempt {
			lightning_payment_attempt_id: row.get("lightning_payment_attempt_id"),
			lightning_invoice_id: row.get("lightning_invoice_id"),
			lightning_node_id: row.get("lightning_node_id"),
			amount_msat: row.get::<_, i64>("amount_msat") as u64,
			is_self_payment: row.get::<_, bool>("is_self_payment"),
			status: row.get("status"),
			error: row.get("error"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		}
	}
}

/// The status of a lightning htlc subscription
///
/// Once the server receives an invoice subscription request, its status is `Started`.
/// The server will monitor this invoice for incoming HTLCs
/// Once one of the HTLCs got accepted, the subscription is set to `Completed`
/// If no HTLC is accepted within the subscription lifetime, subscription will
/// get automatically `Terminated`
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Hash, ToSql, FromSql, PartialEq, Eq)]
#[postgres(name = "lightning_htlc_subscription_status")]
pub enum LightningHtlcSubscriptionStatus {
	/// The invoice was created and received HTLCs does not match the invoice yet
	#[postgres(name = "created")]
	Created,
	/// The invoice was accepted because sum of received HTLCs matches the invoice
	#[postgres(name = "accepted")]
	Accepted,
	/// The invoice preimage was revealed and the invoice was settled
	#[postgres(name = "settled")]
	Settled,
	/// The subscription was cancelled
	///
	/// Can be set either manually by the user or automatically by the
	/// server after `htlc_subscription_timeout`
	#[postgres(name = "cancelled")]
	Cancelled,
}

impl Display for LightningHtlcSubscriptionStatus {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			LightningHtlcSubscriptionStatus::Created => f.write_str("created"),
			LightningHtlcSubscriptionStatus::Accepted => f.write_str("accepted"),
			LightningHtlcSubscriptionStatus::Settled => f.write_str("settled"),
			LightningHtlcSubscriptionStatus::Cancelled => f.write_str("cancelled"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct LightningHtlcSubscription {
	pub lightning_htlc_subscription_id: i64,
	pub lightning_invoice_id: i64,
	pub lightning_node_id: ClnNodeId,
	pub invoice: Bolt11Invoice,
	pub status: LightningHtlcSubscriptionStatus,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl <'a>TryFrom<&'a Row> for LightningHtlcSubscription {
	type Error = anyhow::Error;

	fn try_from(row: &'a Row) -> Result<Self, Self::Error> {
		let invoice = Bolt11Invoice::from_str(row.get("invoice"))?;

		Ok(LightningHtlcSubscription {
			lightning_htlc_subscription_id: row.get("lightning_htlc_subscription_id"),
			lightning_invoice_id: row.get("lightning_invoice_id"),
			lightning_node_id: row.get("lightning_node_id"),
			invoice: invoice,
			status: row.get("status"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
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


/// A type that actually represents a [SecretNonce] but without the
/// typesystem defenses for dangerous usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DangerousSecretNonce(Vec<u8>);

impl DangerousSecretNonce {
	pub fn new(n: SecretNonce) -> Self {
		DangerousSecretNonce(n.dangerous_into_bytes().to_vec())
	}

	pub fn to_sec_nonce(&self) -> SecretNonce {
		assert_eq!(self.0.len(), MUSIG_SECNONCE_SIZE);
		SecretNonce::dangerous_from_bytes(TryFrom::try_from(&self.0[..]).expect("right size"))
	}
}

mod serde {
	use std::fmt;
	use serde::{Deserializer, Serializer};
	use crate::serde_util::Bytes;

	pub mod pub_nonces {
		use super::*;
		use serde::ser::SerializeSeq;
		use ark::musig::PublicNonce;

		pub fn serialize<S: Serializer>(nonces: &Vec<PublicNonce>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PublicNonce>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<PublicNonce>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of public musig nonces")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(PublicNonce::from_byte_array(
							&TryFrom::try_from(e.0.as_ref()).map_err(serde::de::Error::custom)?
						).map_err(serde::de::Error::custom)?);
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
		use ark::musig::PartialSignature;

		pub fn serialize<S: Serializer>(nonces: &Vec<PartialSignature>, s: S) -> Result<S::Ok, S::Error> {
			let mut seq = s.serialize_seq(Some(nonces.len()))?;
			for nonce in nonces {
				seq.serialize_element(&Bytes(nonce.serialize()[..].into()))?;
			}
			seq.end()
		}

		pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<PartialSignature>, D::Error> {
			struct Visitor;

			impl<'de> serde::de::Visitor<'de> for Visitor {
				type Value = Vec<PartialSignature>;

				fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
					f.write_str("a list of partial musig signatures")
				}

				fn visit_seq<A>(self, mut s: A) -> Result<Self::Value, A::Error>
					where A: serde::de::SeqAccess<'de>,
				{
					let mut ret = Vec::with_capacity(s.size_hint().unwrap_or(0));
					while let Some(e) = s.next_element::<Bytes>()? {
						ret.push(PartialSignature::from_byte_array(
							&TryFrom::try_from(e.0.as_ref()).map_err(serde::de::Error::custom)?
						).map_err(serde::de::Error::custom)?);
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
	use bitcoin::hex::{DisplayHex, FromHex};
	use bitcoin::key::Keypair;
	use bitcoin::secp256k1::rand;
	use ark::musig;
	use crate::SECP;

	#[test]
	fn forfeit_state_encoding() {
		// first test random roundtrip
		let key = Keypair::new(&*SECP, &mut rand::thread_rng());
		let (secn, pubn) = musig::nonce_pair(&key);
		let part = PartialSignature::from_byte_array(
			&FromHex::from_hex("fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843").unwrap(),
		).unwrap();

		let ffs = ForfeitState {
			round_id: RoundId::from_slice(&[0u8; 32][..]).unwrap(),
			user_nonces: vec![pubn, pubn],
			user_part_sigs: vec![part, part],
			pub_nonces: vec![pubn, pubn],
			sec_nonces: vec![DangerousSecretNonce::new(secn)],
		};
		let encoded = rmp_serde::to_vec_named(&ffs).unwrap();
		let decoded = rmp_serde::from_slice(&encoded[..]).unwrap();
		assert_eq!(ffs, decoded);

		// then test stability
		let bytes = Vec::<u8>::from_hex("85a8726f756e645f6964c4200000000000000000000000000000000000000000000000000000000000000000ab757365725f6e6f6e63657392c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507ae757365725f706172745f7369677392c420fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843c420fe2b5cf922855b8318ba6224da3b0adabc0d9de4254b47d9687846861aa0f843aa7075625f6e6f6e63657392c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507c4420267390f9da47a07b025839c8efcb1a7bde7cf811f83aa2492924a7144054779ee03c3386f8699df043c23d3da71f7f72b9b70157f97b34546de54efc5c0f8af4507aa7365635f6e6f6e63657391dc0084220eccdcccf10f4f42ccefcc89cc85cccc407bcc9e74ccefcce8454c695fcc86cce6cc86ccd9ccd779cc83ccbdcc97ccfeccd14a3bcce57268ccb073ccd8ccb3cc9810ccfc2e0735ccb6ccd6ccf832044e78ccb004cceecc9505434f10cc875eccfb453d7c30ccefcc8cccb740066025cc8eccdd0fccd90709cce30d017dcccfcccf12ccfdccf37fcce220ccdfcce7ccc1537563ccb3357339ccac09ccacccf31cccb8cc9c09cc8cccab144bcc826078ccfd11cc940d48ccd01dcc95ccd82c56cca9ccda").unwrap();
		let stable = rmp_serde::from_slice::<ForfeitState>(&bytes).unwrap();
		let encoded = rmp_serde::to_vec_named(&stable).unwrap();
		assert_eq!(bytes.as_hex().to_string(), encoded.as_hex().to_string());

	}
}
