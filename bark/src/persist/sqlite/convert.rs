use ark::Movement;
use bitcoin::Amount;
use rusqlite::{Result, Row};
use rusqlite::types::{ToSql, ToSqlOutput};

use crate::VtxoState;

impl ToSql for VtxoState {
	fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
		self.as_str().to_sql()
	}
}

pub trait MovementExt {
	fn try_from_row(value: &Row<'_>) -> anyhow::Result<Movement>;
}

impl MovementExt for Movement {
	fn try_from_row(value: &Row<'_>) -> anyhow::Result<Movement> {
		let fees = Amount::from_sat(value.get("fees_sat")?);
		let spends: String = value.get("spends")?;
		let receives: String = value.get("receives")?;

		Ok(Movement {
			id: value.get("id")?,
			destination: value.get("destination")?,
			fees: fees,
			created_at: value.get("created_at")?,
			spends: serde_json::from_str(&spends)?,
			receives: serde_json::from_str(&receives)?,
		})
	}
}