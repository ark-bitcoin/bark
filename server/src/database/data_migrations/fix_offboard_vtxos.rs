use anyhow::{bail, Context};
use bitcoin::Amount;
use futures::StreamExt;

use tokio_postgres::types::Type;

use ark::encode::ProtocolEncoding;
use ark::ServerVtxo;
use ark::vtxo::Bare;
use ark::vtxo::policy::ServerVtxoPolicy;
use bitcoin_ext::P2TR_DUST;

use crate::database::Db;
use crate::database::model::{SpendState, VtxoState};

const NOARG: &[&bool] = &[];

/// Fix offboard connector and forfeit vtxo rows stored with an empty blob.
///
/// Offboard connector and forfeit vtxos used to be stored with an empty
/// `vtxo` blob, and the connector outputs paid a fresh per-offboard key
/// that was never persisted. Two consequences:
///
/// - Any of these rows entering the watchman frontier makes the frontier
///   unreadable, because `ServerVtxo::deserialize` fails on the empty blob.
///   The legacy startup path (`get_unfrontiered_funding_txids`) pulls them
///   in on the first watchman restart after an offboard.
/// - The connector rows record a bare server-key p2tr while the on-chain
///   output pays the lost ephemeral key, so they can never be swept.
///
/// For every affected row (only pre-fix code wrote empty blobs), the blob
/// is rebuilt from the row's columns. Connector rows are additionally taken
/// out of the watchman's reach permanently: their dust is unrecoverable and
/// any sweep attempt would just broadcast invalid transactions forever.
///
/// Forfeit rows also recorded the forfeit amount without the connector dust
/// that the forfeit tx output accumulates, which would equally invalidate a
/// sweep (the keyspend sighash commits to the prevout value), so their
/// amount is corrected along the way.
pub async fn run(db: &Db) -> anyhow::Result<u64> {
	let reader = db.get_conn().await.context("reader connection")?;
	let writer = db.get_conn().await.context("writer connection")?;

	let select = reader.prepare(
		"SELECT id, vtxo_id, expiry, exit_delta, policy_type, policy, \
			server_pubkey, amount, anchor_point, \
			oor_spent_txid, spent_in_round, offboarded_in, \
			banned_until_height, confirmed_height, \
			spend_state::TEXT AS spend_state, created_at, updated_at \
		 FROM vtxo \
		 WHERE spend_state IN ('offboard-connector', 'offboard-forfeit') \
		 AND length(vtxo) = 0",
	).await.context("preparing select")?;

	let update_forfeit = writer.prepare_typed(
		"UPDATE vtxo SET vtxo = $2, amount = $3, updated_at = NOW() WHERE id = $1",
		&[Type::INT8, Type::BYTEA, Type::INT8],
	).await.context("preparing forfeit update")?;

	// Setting frontier_at keeps get_unfrontiered_funding_txids from pulling
	// the row into the frontier at watchman startup; onchain_spent_height
	// keeps it out of get_frontier. Height 0 is a sentinel that no reorg
	// rollback can clear, since reorg_frontier only clears heights above the
	// fork point.
	// We are effectively throwing out the old connector VTXOs and giving up the dust.
	let update_connector = writer.prepare_typed(
		"UPDATE vtxo \
		 SET vtxo = $2, \
		     frontier_at = COALESCE(frontier_at, NOW()), \
		     onchain_spent_height = COALESCE(onchain_spent_height, 0), \
		     updated_at = NOW() \
		 WHERE id = $1",
		&[Type::INT8, Type::BYTEA],
	).await.context("preparing connector update")?;

	let rows = reader.query_raw(&select, NOARG).await
		.context("selecting offboard vtxos")?;
	tokio::pin! { rows };

	let mut connectors: u64 = 0;
	let mut connector_value: Amount = Amount::ZERO;
	let mut forfeits: u64 = 0;

	while let Some(row) = rows.next().await {
		let row = row.context("reading vtxo row")?;
		let vs = VtxoState::<Bare, ServerVtxoPolicy>::try_from(row)
			.context("reconstructing bare vtxo from row")?;

		match vs.spend_state {
			SpendState::OffboardConnector => {
				connectors += 1;
				connector_value += vs.vtxo.amount();
				let blob = vs.vtxo.serialize();
				writer.execute(&update_connector, &[&vs.id, &blob.as_slice()]).await
					.with_context(|| format!("failed to update vtxo id={}", vs.id))?;
			},
			SpendState::OffboardForfeit => {
				forfeits += 1;
				// pre-fix rows also recorded the forfeit amount without the
				// connector dust that the forfeit tx output accumulates
				let vtxo = ServerVtxo::new(
					vs.vtxo.point(),
					vs.vtxo.policy().clone(),
					vs.vtxo.amount() + P2TR_DUST,
					vs.vtxo.expiry_height(),
					vs.vtxo.server_pubkey(),
					vs.vtxo.exit_delta(),
					vs.vtxo.chain_anchor(),
				);
				let blob = vtxo.serialize();
				let amount = vtxo.amount().to_sat() as i64;
				writer.execute(&update_forfeit, &[&vs.id, &blob.as_slice(), &amount]).await
					.with_context(|| format!("failed to update vtxo id={}", vs.id))?;
			},
			other => bail!("row id={} has unexpected spend state {}", vs.id, other),
		}
	}

	eprintln!("fix_offboard_vtxos: done — removed {} connector (total {}) \
		and fixed {} forfeit vtxos",
		connectors, connector_value, forfeits,
	);
	Ok(connectors + forfeits)
}
