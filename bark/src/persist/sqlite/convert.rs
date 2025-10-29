
use std::borrow::Borrow;
use std::fmt;

use bitcoin::Amount;
use bitcoin::hex::FromHex;
use rusqlite::types::FromSql;
use rusqlite::{Row, RowIndex, Rows};

use ark::{ProtocolEncoding, Vtxo};

use crate::movement::old;
use crate::vtxo_state::VtxoState;
use crate::WalletVtxo;

#[allow(unused)]
pub trait RowExt<'a>: Borrow<Row<'a>> {
	/// We need the value from a potentially optional column
	fn need<I, T>(&self, idx: I) -> anyhow::Result<T>
	where
		I: RowIndex + Clone + fmt::Display,
		T: FromSql,
	{
		match self.borrow().get::<I, Option<T>>(idx.clone())? {
			Some(v) => Ok(v),
			None => bail!("missing value for column '{}'", idx),
		}
	}
}

impl<'a> RowExt<'a> for Row<'a> {}

pub (crate) fn row_to_movement_old(row: &Row<'_>) -> anyhow::Result<old::Movement> {
	let fees: Amount = Amount::from_sat(row.get("fees_sat")?);

	let kind = old::MovementKind::from_str(&row.get::<_, String>("kind")?)?;
	let spends = serde_json::from_str::<Vec<String>>(&row.get::<_, String>("spends")?)?
		.iter()
		.map(|v| {
			let bytes = Vec::<u8>::from_hex(v).expect("corrupt db");
			Vtxo::deserialize(&bytes)
		})
		.collect::<Result<Vec<Vtxo>, _>>()?;

	let receives = serde_json::from_str::<Vec<String>>(&row.get::<_, String>("receives")?)?
		.iter()
		.map(|v| {
			let bytes = Vec::<u8>::from_hex(v).expect("corrupt db");
			Vtxo::deserialize(&bytes)
		})
		.collect::<Result<Vec<Vtxo>, _>>()?;


	let recipients = serde_json::from_str::<Vec<old::MovementRecipient>>(&row.get::<_, String>("recipients")?)?;

	Ok(old::Movement {
		id: row.get("id")?,
		kind: kind,
		fees: fees,
		spends: spends,
		receives: receives,
		recipients: recipients,
		created_at: row.get("created_at")?,
	})
}

pub (crate) fn row_to_wallet_vtxo(row: &Row<'_>) -> anyhow::Result<WalletVtxo> {
	let raw_vtxo = row.get::<_, Vec<u8>>("raw_vtxo")?;
	let vtxo = Vtxo::deserialize(&raw_vtxo)?;

	let state = serde_json::from_slice::<VtxoState>(&row.get::<_, Vec<u8>>("state")?)?;
	Ok(WalletVtxo { vtxo, state })
}

pub (crate) fn rows_to_wallet_vtxos(mut rows: Rows<'_>) -> anyhow::Result<Vec<WalletVtxo>> {
	let mut vtxos = Vec::new();
	while let Some(row) = rows.next()? {
		vtxos.push(row_to_wallet_vtxo(&row)?);
	}
	Ok(vtxos)
}
