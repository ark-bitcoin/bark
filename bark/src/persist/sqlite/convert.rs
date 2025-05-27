use ark::util::Decodable;
use bitcoin::Amount;
use rusqlite::{Result, Row};
use rusqlite::types::{ToSql, ToSqlOutput};

use crate::movement::{Movement, MovementRecipient, VtxoSubset};
use crate::{OffchainOnboard, OffchainPayment, VtxoState};

impl ToSql for VtxoState {
	fn to_sql(&self) -> Result<ToSqlOutput<'_>> {
		self.as_str().to_sql()
	}
}

pub (crate) fn row_to_movement(row: &Row<'_>) -> anyhow::Result<Movement> {
	let fees: Amount = Amount::from_sat(row.get("fees_sat")?);

	let spends = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("spends")?)?;
	let receives = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("receives")?)?;
	let recipients = serde_json::from_str::<Vec<MovementRecipient>>(&row.get::<_, String>("recipients")?)?;

	Ok(Movement {
		id: row.get("id")?,
		fees: fees,
		spends: spends,
		receives: receives,
		recipients: recipients,
		created_at: row.get("created_at")?,
	})
}

pub (crate) fn row_to_offchain_onboard(row: &Row<'_>) -> anyhow::Result<OffchainOnboard> {
	Ok(OffchainOnboard {
		payment_hash: row.get("payment_hash")?,
		payment_preimage: row.get("preimage")?,
		payment: OffchainPayment::decode(&row.get::<_, Vec<u8>>("serialised_payment")?)?,
	})
}
