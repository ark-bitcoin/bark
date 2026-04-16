
use std::collections::BTreeMap;

use bitcoin::Txid;
use tokio_postgres::types::Type;

use ark::{ProtocolEncoding, ServerVtxo, VtxoId};
use bitcoin_ext::BlockHeight;
use tokio_stream::StreamExt;

use crate::database::{Db, NOARG};

impl Db {
	/// Add all vtxos whose vtxo_txid matches `funding_txid` to the frontier.
	///
	/// Used when a new funding tx is registered (finish_round, register_board,
	/// vtxopool issuance) so the watchman can pick them up without a full scan.
	/// Pass `confirmed_height` when the funding tx is already confirmed on-chain
	/// (e.g. board vtxos), or `None` when it is still unconfirmed.
	pub async fn add_funding_vtxos_to_frontier(
		&self,
		funding_txid: Txid,
		confirmed_height: Option<BlockHeight>,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		conn.execute(
			"INSERT INTO watchman_vtxo_frontier (vtxo_id, confirmed_height)
			SELECT vtxo_id, $2 FROM vtxo WHERE vtxo_txid = $1
			ON CONFLICT DO NOTHING",
			&[&funding_txid.to_string(), &confirmed_height.map(|h| h as i32)],
		).await?;

		Ok(())
	}

	/// Add a new vtxo to the frontier table.
	pub async fn add_vtxo_to_frontier(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"INSERT INTO watchman_vtxo_frontier (vtxo_id) VALUES ($1) ON CONFLICT DO NOTHING",
			&[Type::TEXT],
		).await?;

		conn.execute(&stmt, &[&vtxo_id.to_string()]).await?;

		Ok(())
	}

	/// Register a confirmation for a vtxo at a given block height.
	pub async fn register_vtxo_confirmation(
		&self,
		vtxo_id: VtxoId,
		height: BlockHeight,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"UPDATE watchman_vtxo_frontier SET confirmed_height = $2 WHERE vtxo_id = $1",
			&[Type::TEXT, Type::INT4],
		).await?;

		conn.execute(&stmt, &[&vtxo_id.to_string(), &(height as i32)]).await?;

		Ok(())
	}

	/// Register a spend for a vtxo at a given block height and txid.
	pub async fn register_vtxo_spend(
		&self,
		vtxo_id: VtxoId,
		height: BlockHeight,
		txid: Txid,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"UPDATE watchman_vtxo_frontier SET spent_height = $2, spent_txid = $3 WHERE vtxo_id = $1",
			&[Type::TEXT, Type::INT4, Type::TEXT],
		).await?;

		conn.execute(&stmt, &[&vtxo_id.to_string(), &(height as i32), &txid.to_string()]).await?;

		Ok(())
	}

	/// Get the current frontier: all vtxos that are not yet spent, grouped by confirmation height.
	pub async fn get_frontier(
		&self,
	) -> anyhow::Result<BTreeMap<VtxoId, (Option<BlockHeight>, ServerVtxo)>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare("
			SELECT f.confirmed_height, v.vtxo FROM watchman_vtxo_frontier f
			JOIN vtxo v ON f.vtxo_id = v.vtxo_id
			WHERE f.spent_height IS NULL
		").await?;

		let mut frontier = BTreeMap::new();

		let rows = conn.query_raw(&stmt, NOARG).await?;
		tokio::pin! { rows };
		while let Some(row) = rows.next().await {
			let row = row?;
			let confirmed_height: Option<i32> = row.get("confirmed_height");
			let confirmed_height = confirmed_height.map(|h| h as BlockHeight);
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			frontier.insert(vtxo.id(), (confirmed_height, vtxo));
		}

		Ok(frontier)
	}

	/// Get frontier vtxos that were created after `since`, used for the periodic
	/// in-memory sync. Returns unspent entries so the caller can register any
	/// that are not yet in the in-memory frontier.
	pub async fn get_frontier_vtxos_since(
		&self,
		since: chrono::DateTime<chrono::Utc>,
	) -> anyhow::Result<Vec<(ServerVtxo, Option<BlockHeight>)>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed("
			SELECT f.confirmed_height, v.vtxo
			FROM watchman_vtxo_frontier f
			JOIN vtxo v ON f.vtxo_id = v.vtxo_id
			WHERE v.created_at > $1 AND f.spent_height IS NULL
		", &[Type::TIMESTAMPTZ]).await?;

		let rows = conn.query(&stmt, &[&since]).await?;

		rows.iter().map(|row| {
			let confirmed_height: Option<i32> = row.get("confirmed_height");
			let confirmed_height = confirmed_height.map(|h| h as BlockHeight);
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			Ok((vtxo, confirmed_height))
		}).collect()
	}

	/// Get all vtxos that originate from a specific transaction.
	pub async fn get_vtxos_by_txid(&self, txid: Txid) -> anyhow::Result<Vec<ServerVtxo>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"SELECT vtxo FROM vtxo WHERE vtxo_txid = $1",
			&[Type::TEXT],
		).await?;

		let rows = conn.query(&stmt, &[&txid.to_string()]).await?;

		rows.iter().map(|row| Ok(ServerVtxo::deserialize(row.get("vtxo"))?)).collect()
	}

	/// Get all funding transaction txids that have vtxos not yet in the frontier.
	///
	/// TODO: remove this once all deployments have run with finish_round adding
	/// vtxos directly to the frontier. It is only called once at startup now.
	pub async fn get_unfrontiered_funding_txids(&self) -> anyhow::Result<Vec<Txid>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare("
			SELECT DISTINCT v.vtxo_txid
			FROM vtxo v
			JOIN virtual_transaction vt ON vt.txid = v.vtxo_txid AND vt.is_funding = true
			WHERE NOT EXISTS (
				SELECT 1 FROM watchman_vtxo_frontier f WHERE f.vtxo_id = v.vtxo_id
			)
		").await?;

		let rows = conn.query(&stmt, &[]).await?;

		rows.iter()
			.map(|row| {
				let txid_str: String = row.get("vtxo_txid");
				Ok(txid_str.parse()?)
			})
			.collect()
	}

	/// Rollback frontier state after a chain reorg.
	/// Clears confirmed_height and spent data for entries above the fork point.
	pub async fn reorg_frontier(&self, height: BlockHeight) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare_typed(
			"UPDATE watchman_vtxo_frontier SET confirmed_height = NULL WHERE confirmed_height > $1",
			&[Type::INT4],
		).await?;
		conn.execute(&stmt, &[&(height as i32)]).await?;

		let stmt = conn.prepare_typed(
			"UPDATE watchman_vtxo_frontier SET spent_height = NULL, spent_txid = NULL WHERE spent_height > $1",
			&[Type::INT4],
		).await?;
		conn.execute(&stmt, &[&(height as i32)]).await?;

		Ok(())
	}
}
