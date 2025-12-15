use anyhow::Context;

use std::str::FromStr;

use bitcoin::{Transaction, Txid};
use bitcoin::consensus::deserialize;
use chrono::{DateTime, Local};
use tokio_postgres::Row;

use bitcoin_ext::BlockHeight;
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
	/// If this is a board vtxo, the time at which it was swept.
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl VtxoState {
	pub fn is_spendable(&self) -> bool {
		self.oor_spent_txid.is_none() && self.spent_in_round.is_none()
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

#[derive(Debug, Clone)]
pub struct Board {
	pub id: i64,
	pub vtxo_id: VtxoId,
	pub expiry_height: BlockHeight,
	pub exited_at: Option<DateTime<Local>>,
	pub swept_at: Option<DateTime<Local>>,
	pub created_at: DateTime<Local>,
	pub updated_at: DateTime<Local>,
}

impl TryFrom<Row> for Board {

	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		let vtxo_id = VtxoId::from_str(row.get::<_, &str>("vtxo_id"))?;
		let expiry_height = BlockHeight::try_from(row.get::<_, i32>("expiry_height"))
			.context("Invalid blockheight")?;
		let exited_at = row.get("exited_at");
		let swept_at = row.get("swept_at");
		let created_at = row.get("created_at");
		let updated_at = row.get("updated_at");

		Ok(Self {
			id: row.get("id"),
			vtxo_id,
			expiry_height,
			exited_at,
			swept_at,
			created_at,
			updated_at,
		})
	}
}
