use std::borrow::Cow;
use std::str::FromStr;

use anyhow::Context;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use ark::{ProtocolEncoding, Vtxo, VtxoId};


// Used by mailbox as an always increasing number for data sorting.
pub type Checkpoint = u64;

#[derive(Debug)]
pub struct VtxoState {
	pub id: i64,
	/// The id of the VTXO
	pub vtxo_id: VtxoId,

	/// The raw vtxo encoded.
	pub vtxo: Vtxo,
	// NB keep this type explicit as u32 instead of BlockHeight to ensure encoding is stable
	pub expiry: u32,

	/// If this vtxo was spent in an OOR tx, the txid of the OOR tx.
	pub oor_spent_txid: Option<Txid>,

	/// The round id this vtxo was forfeited in.
	pub spent_in_round: Option<i64>,

	/// If this VTXO was offboarded, the offboard tx's txid
	pub offboarded_in: Option<Txid>,

	/// If this is a board vtxo, the time at which it was swept.
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent_txid.is_none()
			&& self.spent_in_round.is_none()
			&& self.offboarded_in.is_none()
	}
}

impl AsRef<Vtxo> for VtxoState {
	fn as_ref(&self) -> &Vtxo {
	    &self.vtxo
	}
}

impl TryFrom<Row> for VtxoState {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
		debug_assert_eq!(vtxo_id, vtxo.id());

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			vtxo,
			expiry: u32::try_from(row.get::<_, i32>("expiry"))?,
			oor_spent_txid: row
				.get::<_, Option<&str>>("oor_spent_txid")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			spent_in_round: row.get("spent_in_round"),
			offboarded_in: row
				.get::<_, Option<&str>>("offboarded_in")
				.map(|txid| Txid::from_str(txid))
				.transpose()?,
			created_at: row.get("created_at"),
			updated_at: row.get("updated_at"),
		})
	}
}

#[derive(Debug, Clone)]
pub struct Sweep {
	pub txid: Txid,
	pub tx: Transaction
}

impl TryFrom<Row> for Sweep {
	type Error = anyhow::Error;

	fn try_from(value: Row) -> Result<Self, Self::Error> {
		let txid = Txid::from_str(&value.get::<_, String>("txid"))?;
		let tx = deserialize::<Transaction>(value.get("tx"))?;
		debug_assert_eq!(tx.compute_txid(), txid);

		Ok(Self { txid, tx })
	}
}

/// A persisted virtual transaction
#[derive(Debug, Clone)]
pub struct VirtualTransaction<'a> {
	/// The [bitcoin::Txid] of the transaction
	pub txid: Txid,
	/// If we know the signatures this contains the signed transaction
	/// This is empty if the signature isn't known (yet)
	pub signed_tx: Option<Cow<'a, Transaction>>,
	/// True if this is a funding transaction
	pub is_funding: bool,
	/// The datetime when an descendant became server-owned, or `None` if all
	/// descendants are client-owned. When set, the server MUST ensure `signed_tx`
	/// is populated.
	pub server_may_own_descendant_since: Option<DateTime<Local>>,
}

impl<'a> VirtualTransaction<'a> {
	pub fn signed_tx(&self) -> Option<&Transaction> {
		self.signed_tx.as_deref()
	}

	/// Returns true if an descendant of this transaction is owned by the server.
	pub fn server_may_own_descendant(&self) -> bool {
		self.server_may_own_descendant_since.is_some()
	}

	pub fn new_unsigned(txid: Txid) -> Self {
		Self { txid, signed_tx: None, is_funding: false, server_may_own_descendant_since: None }
	}

	pub fn new_signed_ref(tx: &'a Transaction) -> Self {
		Self {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Borrowed(tx)),
			is_funding: false,
			server_may_own_descendant_since: None,
		}
	}

	pub fn new_signed_owned(tx: Transaction) -> VirtualTransaction<'static> {
		VirtualTransaction {
			txid: tx.compute_txid(),
			signed_tx: Some(Cow::Owned(tx)),
			is_funding: false,
			server_may_own_descendant_since: None,
		}
	}

	pub fn as_funding(mut self) -> Self {
		self.is_funding = true;
		self
	}

	pub fn as_server_owned_since(mut self, since: DateTime<Local>) -> Self {
		self.server_may_own_descendant_since = Some(since);
		self
	}
}


impl TryFrom<Row> for VirtualTransaction<'static> {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		// Parse the txid first. We use it for error messages
		let txid: &str = row.get("txid");
		let txid: Txid = Txid::from_str(txid)
				.with_context(|| format!("Invalid txid {}", txid))?;

		let signed_tx: Option<Cow<'static, Transaction>> = row.get::<_, Option<&[u8]>>("signed_tx")
			.map(|tx| deserialize(tx)).transpose()
			.with_context(|| format!("Failed to parse signed_tx for txid {}", txid))?
			.map(|tx| Cow::Owned(tx));
		let is_funding: bool = row.get("is_funding");
		let server_may_own_descendant_since: Option<DateTime<Local>> =
			row.get("server_may_own_descendant_since");

		Ok(Self { txid, signed_tx, is_funding, server_may_own_descendant_since })
	}
}
