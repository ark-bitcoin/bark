use std::str::FromStr;

use bitcoin::Amount;
use lightning_invoice::Bolt11Invoice;
use rusqlite::Row;
use ark::lightning::{PaymentHash, Preimage};

use crate::movement::{Movement, MovementKind, MovementRecipient, VtxoSubset};
use crate::persist::LightningReceive;

pub (crate) fn row_to_movement(row: &Row<'_>) -> anyhow::Result<Movement> {
	let fees: Amount = Amount::from_sat(row.get("fees_sat")?);

	let kind = MovementKind::from_str(&row.get::<_, String>("kind")?)?;
	let spends = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("spends")?)?;
	let receives = serde_json::from_str::<Vec<VtxoSubset>>(&row.get::<_, String>("receives")?)?;
	let recipients = serde_json::from_str::<Vec<MovementRecipient>>(&row.get::<_, String>("recipients")?)?;

	Ok(Movement {
		id: row.get("id")?,
		kind: kind,
		fees: fees,
		spends: spends,
		receives: receives,
		recipients: recipients,
		created_at: row.get("created_at")?,
	})
}

pub (crate) fn row_to_lightning_receive(row: &Row<'_>) -> anyhow::Result<LightningReceive> {
	let invoice_str = row.get::<_, String>("invoice")?;
	let invoice = Bolt11Invoice::from_str(&invoice_str)?;

	Ok(LightningReceive {
		payment_hash: PaymentHash::from(row.get::<_, [u8; 32]>("payment_hash")?),
		payment_preimage: Preimage::from(row.get::<_, [u8; 32]>("preimage")?),
		preimage_revealed_at: row.get::<_, Option<u64>>("preimage_revealed_at")?,
		invoice: invoice,
	})
}
