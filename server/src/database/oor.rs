use anyhow::Context;

use bitcoin::Txid;

use log::{trace, warn};
use ark::VtxoId;
use tokio_postgres::GenericClient;
use tokio_postgres::types::Type;


pub async fn mark_package_spent<T>(
	client: &T,
	inputs: &[VtxoId],
	spending_txids: &[Txid]
) -> anyhow::Result<()>
	where T: GenericClient
{
	debug_assert_eq!(inputs.len(), spending_txids.len(), "Provided bad inputs");

	let statement = client.prepare_typed("
		UPDATE vtxo
		SET oor_spent_txid = $2, updated_at = NOW()
		WHERE vtxo_id = $1 AND oor_spent_txid IS NULL AND spent_in_round IS NULL",
	&[Type::TEXT, Type::TEXT]).await.context("Failed to prepare query")?;

	for (vtxo_id, spending_txid) in inputs.iter().zip(spending_txids) {
		let nb_rows_affected = client.execute(&statement, &[
			&vtxo_id.to_string(),
			&spending_txid.to_string()
		]).await.context("Failed to execute query")?;


		if nb_rows_affected == 0 {
			trace!("Tried to mark vtxo as spent but no update happened");
			// If we didn't update anything we will first check if the vtxo
			// in the database has the expected state.
			//
			// If this is the case, we just continue. This gives us idempotency (Yippy)
			// Otherwise, we bail
			let statement = client.prepare("SELECT oor_spent_txid FROM vtxo where vtxo_id = $1").await?;
			let row = client.query_one(&statement, &[&vtxo_id.to_string()])
				.await
				.with_context(|| format!("Failed to verify if vtxo {} is spent", vtxo_id))?;

			let stored_spending_txid = row.get::<_, &str>(0);
			trace!("Comparing txids: db {} and request {}", stored_spending_txid, spending_txid.to_string());
			if row.get::<_, &str>(0) != spending_txid.to_string() {
				warn!("Attempt to double-spend a VTXO {} in spending_txid {}", vtxo_id, spending_txid);
				bail!("Failed to mark vtxo {} as spent", vtxo_id);
			}
		}
		if nb_rows_affected > 1 {
			panic!("Database contains multiple vtxos with id {}", vtxo_id)
		}

	}

	Ok(())
}
