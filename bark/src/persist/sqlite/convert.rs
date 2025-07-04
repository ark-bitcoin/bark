use bitcoin::Amount;
use rusqlite::Row;
use ark::lightning::{PaymentHash, Preimage};
use crate::movement::{Movement, MovementRecipient, VtxoSubset};
use crate::persist::OffchainBoard;

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

pub (crate) fn row_to_offchain_board(row: &Row<'_>) -> anyhow::Result<OffchainBoard> {
	let raw_payment = row.get::<_, Vec<u8>>("serialised_payment")?;
	Ok(OffchainBoard {
		payment_hash: PaymentHash::from(row.get::<_, [u8; 32]>("payment_hash")?),
		payment_preimage: Preimage::from(row.get::<_, [u8; 32]>("preimage")?),
		preimage_revealed_at: row.get::<_, Option<u64>>("preimage_revealed_at")?,
		payment: serde_json::from_slice(&raw_payment)?,
	})
}
