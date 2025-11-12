
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use bitcoin::{Amount, SignedAmount};
use bitcoin::hex::FromHex;
use chrono::DateTime;
use rusqlite::{Row, RowIndex, Rows};
use rusqlite::types::FromSql;
use serde::Deserialize;

use ark::{ProtocolEncoding, Vtxo};

use crate::WalletVtxo;
use crate::movement::{old, Movement, MovementId, MovementStatus, MovementSubsystem, MovementTimestamp};
use crate::vtxo::state::VtxoState;

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

pub(crate) fn row_to_movement(row: &Row) -> anyhow::Result<Movement> {
	fn from_json_text_to_vec<T: for<'de> Deserialize<'de>>(json: String) -> anyhow::Result<Vec<T>, rusqlite::Error> {
		if json == "null" {
			Ok(Vec::new())
		} else {
			let r = from_json_text(&json)?;
			Ok(r)
		}
	}
	fn from_json_text<T: for<'de> Deserialize<'de>>(json: &str) -> anyhow::Result<T, rusqlite::Error> {
		serde_json::from_str(json)
			.map_err(|e| rusqlite::Error::FromSqlConversionFailure(
				12, rusqlite::types::Type::Text, Box::new(e),
			))
	}
	Ok(Movement {
		id: MovementId::new(row.get("id")?),
		status: MovementStatus::from_str(&row.get::<&str, String>("status")?)?,
		subsystem: MovementSubsystem {
			name: row.get("subsystem_name")?,
			kind: row.get("movement_kind")?,
		},
		metadata: row.get::<&str, Option<String>>("metadata")?
			.map(|s| from_json_text(&s)).unwrap_or_else(|| Ok(HashMap::new()))?,
		intended_balance: SignedAmount::from_sat(row.get("intended_balance")?),
		effective_balance: SignedAmount::from_sat(row.get("effective_balance")?),
		offchain_fee: Amount::from_sat(row.get("offchain_fee")?),
		sent_to: from_json_text_to_vec(row.get("sent_to")?)?,
		received_on: from_json_text_to_vec(row.get("received_on")?)?,
		input_vtxos: from_json_text_to_vec(row.get("input_vtxos")?)?,
		output_vtxos: from_json_text_to_vec(row.get("output_vtxos")?)?,
		exited_vtxos: from_json_text_to_vec(row.get("exited_vtxos")?)?,
		time: MovementTimestamp {
			created_at: DateTime::from_timestamp(row.get("created_at")?, 0)
				.ok_or_else(|| rusqlite::Error::InvalidQuery)?,
			updated_at: DateTime::from_timestamp(row.get("updated_at")?, 0)
				.ok_or_else(|| rusqlite::Error::InvalidQuery)?,
			completed_at: row.get::<&str, Option<i64>>("completed_at")?
				.and_then(|ts| DateTime::from_timestamp(ts, 0)),
		},
	})
}

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
