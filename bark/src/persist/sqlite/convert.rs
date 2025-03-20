use bitcoin::Amount;
use rusqlite::{Result, Row};
use rusqlite::types::{ToSql, ToSqlOutput};

use crate::movement::{Movement, VtxoSubset};
use crate::VtxoState;

impl ToSql for VtxoState {
	fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
		self.as_str().to_sql()
	}
}

pub (crate) fn row_to_movement(row: &Row<'_>) -> anyhow::Result<Movement> {
	let fees: Amount = Amount::from_sat(row.get("fees_sat")?);

	let spends = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("spends")?)?;
	let receives = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("receives")?)?;

	Ok(Movement {
		id: row.get("id")?,
		destination: row.get("destination")?,
		fees: fees,
		spends: spends,
		receives: receives,
		created_at: row.get("created_at")?,
	})
}