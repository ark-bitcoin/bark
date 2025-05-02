use std::fmt;
use anyhow::Context;
use postgres_types::{FromSql, ToSql};
use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::SecretKey;
use chrono::{DateTime, Utc};
use lightning_invoice::Bolt11Invoice;
use tokio_postgres::Row;

use ark::{Vtxo, VtxoId};
use ark::musig::secpm::schnorr;
use ark::rounds::RoundId;
use ark::tree::signed::SignedVtxoTreeSpec;
use ark::util::Decodable;

use super::ClnNodeId;

#[derive(Debug, Clone)]
pub struct StoredRound {
	pub id: RoundId,
	pub tx: Transaction,
	pub signed_tree: SignedVtxoTreeSpec,
	pub nb_input_vtxos: u64,
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
			nb_input_vtxos: u64::try_from(value.get::<_, i32>("nb_input_vtxos"))?,
			connector_key: SecretKey::from_slice(value.get("connector_key"))?,
		})
	}
}

#[derive(Debug, Clone)]
pub struct VtxoState {
	/// The id of the VTXO
	pub id: VtxoId,
	/// The raw vtxo encoded.
	pub vtxo: Vtxo,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent: Option<Txid>,
	/// The forfeit tx signatures of the user if the vtxo was forfeited.
	pub forfeit_sigs: Option<Vec<schnorr::Signature>>,
	/// If this is an board vtxo, true after it has been swept.
	pub board_swept: bool,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent.is_none() && self.forfeit_sigs.is_none()
	}
}

impl TryFrom<Row> for VtxoState {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(value.get::<_, &str>("id"))?;
		let vtxo = Vtxo::decode(value.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: vtxo_id,
			vtxo,
			expiry: u32::try_from(value.get::<_, i32>("expiry"))?,
			oor_spent: value
				.get::<_, Option<&[u8]>>("oor_spent")
				.map(|tx| deserialize(tx))
				.transpose()?,
			forfeit_sigs: value
				.get::<_, Option<Vec<&[u8]>>>("forfeit_sigs")
				.map(|sigs| sigs
					.into_iter()
					.map(|sig|  Ok(schnorr::Signature::from_byte_array(sig.try_into()?)))
					.collect::<anyhow::Result<Vec<_>>>()
				)
				.transpose()?,
			board_swept: value.get::<_, bool>("board_swept"),
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
	pub payment_status: LightningPaymentStatus,
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
			payment_status: row.get("payment_status"),
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
	pub amount_msat: Option<u64>,
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
			amount_msat: row.get::<_, Option<i64>>("amount_msat").map(|i| i as u64),
			status: row.get("status"),
			error: row.get("error"),
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		}
	}
}
