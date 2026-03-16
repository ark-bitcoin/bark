use anyhow::Context;
use futures::StreamExt;
use tokio::time::Instant;
use tokio_postgres::types::Type;
use tracing::{debug, info};

use ark::ServerVtxo;
use ark::encode::ProtocolEncoding;
use ark::vtxo::Full;

use crate::database::Db;

const NOARG: &[&bool] = &[];

/// Fill in the exit_delta, policy_type, policy, server_pubkey, amount and
/// anchor_point columns for all vtxos that still have NULL values.
///
/// The data is extracted from the serialized vtxo blob which already
/// contains all of this information.
///
/// Uses two separate connections: one to stream rows and one to write
/// updates, so we never need to buffer the entire table in memory.
pub async fn run(db: &Db) -> anyhow::Result<u64> {
	let reader = db.get_conn().await.context("reader connection")?;
	let writer = db.get_conn().await.context("writer connection")?;

	let total: i64 = reader.query_one(
		"SELECT COUNT(*) FROM vtxo WHERE exit_delta IS NULL", &[],
	).await.context("counting vtxos")?.get(0);

	if total == 0 {
		info!("fill_vtxo_data: nothing to do, no vtxos in table");
		return Ok(0);
	}

	info!("fill_vtxo_data: backfilling {} vtxos", total);

	let select = reader.prepare("SELECT id, vtxo FROM vtxo WHERE exit_delta IS NULL")
		.await.context("preparing select")?;

	let update = writer.prepare_typed("
		UPDATE vtxo
		SET exit_delta = $2,
		    policy_type = $3,
		    policy = $4,
		    server_pubkey = $5,
		    amount = $6,
		    anchor_point = $7,
		    updated_at = NOW()
		WHERE id = $1
	", &[Type::INT8, Type::INT4, Type::TEXT, Type::BYTEA, Type::TEXT, Type::INT8, Type::TEXT])
		.await.context("preparing update")?;

	let rows = reader.query_raw(&select, NOARG).await
		.context("selecting vtxos with missing data")?;
	tokio::pin! { rows };

	let mut count: u64 = 0;
	let mut last_log = Instant::now();
	while let Some(row) = rows.next().await {
		let row = row.context("reading vtxo row")?;
		let id: i64 = row.get("id");
		let vtxo_bytes: &[u8] = row.get("vtxo");

		let vtxo = ServerVtxo::<Full>::deserialize(vtxo_bytes)
			.with_context(|| format!("failed to deserialize vtxo with id {}", id))?;

		let exit_delta = vtxo.exit_delta() as i32;
		let policy_type = vtxo.policy_type().to_string();
		let policy = vtxo.policy().serialize();
		let server_pubkey = vtxo.server_pubkey().to_string();
		let amount = vtxo.amount().to_sat() as i64;
		let anchor_point = vtxo.chain_anchor().to_string();

		writer.execute(
			&update,
			&[&id, &exit_delta, &policy_type, &policy, &server_pubkey, &amount, &anchor_point],
		).await
			.with_context(|| format!("failed to update vtxo with id {}", id))?;

		count += 1;

		if last_log.elapsed() >= std::time::Duration::from_secs(1) {
			debug!("fill_vtxo_data: processed {} out of {} vtxos", count, total);
			last_log = Instant::now();
		}
	}

	info!("fill_vtxo_data: backfilled {} vtxos", count);
	Ok(count)
}
