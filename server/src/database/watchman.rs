
use std::collections::BTreeMap;

use bitcoin::Txid;
use tokio_postgres::types::Type;

use ark::{ProtocolEncoding, ServerVtxo, VtxoId};
use bitcoin_ext::BlockHeight;
use tokio_stream::StreamExt;

use crate::database::{Tx, NOARG};

impl<'t> Tx<'t> {
	/// Add all vtxos whose vtxo_txid matches `funding_txid` to the frontier.
	///
	/// Used when a new funding tx is registered (finish_round, register_board,
	/// vtxopool issuance) so the watchman can pick them up without a full scan.
	/// Pass `confirmed_height` when the funding tx is already confirmed on-chain
	/// (e.g. board vtxos), or `None` when it is still unconfirmed.
	///
	/// `frontier_at` is preserved on rows that were already frontiered. A
	/// supplied `confirmed_height` overwrites any existing value — callers
	/// pass it straight from a fresh bitcoind observation, which is more
	/// reliable than what's already on the row (e.g. across reorgs).
	pub async fn add_funding_vtxos_to_frontier(
		&self,
		funding_txid: Txid,
		confirmed_height: Option<BlockHeight>,
	) -> anyhow::Result<()> {
		self.execute("
			UPDATE vtxo
			SET frontier_at = COALESCE(frontier_at, NOW()),
				confirmed_height = COALESCE($2::int4, confirmed_height),
				updated_at = NOW()
			WHERE vtxo_txid = $1
			AND (frontier_at IS NULL
				OR ($2::int4 IS NOT NULL
					AND confirmed_height IS DISTINCT FROM $2::int4))
		", &[&funding_txid.to_string(), &confirmed_height.map(|h| h as i32)]).await?;

		Ok(())
	}

	/// Add a new vtxo to the frontier.
	///
	/// Idempotent: a no-op if the vtxo is already in the frontier.
	pub async fn add_vtxo_to_frontier(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		let stmt = self.prepare_typed("
			UPDATE vtxo SET frontier_at = NOW(), updated_at = NOW()
			WHERE vtxo_id = $1 AND frontier_at IS NULL
		", &[Type::TEXT]).await?;

		self.execute(&stmt, &[&vtxo_id.to_string()]).await?;

		Ok(())
	}

	/// Register a confirmation for a vtxo at a given block height.
	///
	/// The `IS DISTINCT FROM` guard skips the UPDATE when the value is
	/// unchanged. Plain `<>` would silently filter out rows where
	/// `confirmed_height IS NULL` (since `NULL <> $2` is NULL, not true), so
	/// the first confirmation would never land. `IS DISTINCT FROM` is the
	/// NULL-safe inequality and treats NULL as a comparable value, which is
	/// what we want here. Avoiding no-op updates matters because every
	/// UPDATE fires `vtxo_update_trigger` and writes a `vtxo_history` row.
	pub async fn register_vtxo_confirmation(
		&self,
		vtxo_id: VtxoId,
		height: BlockHeight,
	) -> anyhow::Result<()> {
		let stmt = self.prepare_typed("
			UPDATE vtxo SET confirmed_height = $2, updated_at = NOW()
			WHERE vtxo_id = $1 AND confirmed_height IS DISTINCT FROM $2::int4
		", &[Type::TEXT, Type::INT4]).await?;

		self.execute(&stmt, &[&vtxo_id.to_string(), &(height as i32)]).await?;

		Ok(())
	}

	/// Register a spend for a vtxo at a given block height and txid.
	pub async fn register_vtxo_spend(
		&self,
		vtxo_id: VtxoId,
		height: BlockHeight,
		txid: Txid,
	) -> anyhow::Result<()> {
		let stmt = self.prepare_typed("
			UPDATE vtxo
			SET onchain_spent_height = $2, onchain_spent_txid = $3, updated_at = NOW()
			WHERE vtxo_id = $1 AND onchain_spent_height IS NULL
		", &[Type::TEXT, Type::INT4, Type::TEXT]).await?;

		self.execute(&stmt, &[&vtxo_id.to_string(), &(height as i32), &txid.to_string()]).await?;

		Ok(())
	}

	/// Get the current frontier: all vtxos that are in the frontier and not yet
	/// spent on-chain, grouped by confirmation height.
	pub async fn get_frontier(
		&self,
	) -> anyhow::Result<BTreeMap<VtxoId, (Option<BlockHeight>, ServerVtxo)>> {
		let stmt = self.prepare("
			SELECT confirmed_height, vtxo FROM vtxo
			WHERE frontier_at IS NOT NULL AND onchain_spent_height IS NULL
		").await?;

		let mut frontier = BTreeMap::new();

		let rows = self.query_raw(&stmt, NOARG).await?;
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

	/// Get frontier vtxos that joined the frontier after `since`, used for the
	/// periodic in-memory sync. Returns unspent entries so the caller can
	/// register any that are not yet in the in-memory frontier.
	pub async fn get_frontier_vtxos_since(
		&self,
		since: chrono::DateTime<chrono::Utc>,
	) -> anyhow::Result<Vec<(ServerVtxo, Option<BlockHeight>)>> {
		let stmt = self.prepare_typed("
			SELECT confirmed_height, vtxo FROM vtxo
			WHERE frontier_at > $1 AND onchain_spent_height IS NULL
		", &[Type::TIMESTAMPTZ]).await?;

		let rows = self.query(&stmt, &[&since]).await?;

		rows.iter().map(|row| {
			let confirmed_height: Option<i32> = row.get("confirmed_height");
			let confirmed_height = confirmed_height.map(|h| h as BlockHeight);
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			Ok((vtxo, confirmed_height))
		}).collect()
	}

	/// Get all vtxos that originate from a specific transaction.
	pub async fn get_vtxos_by_txid(&self, txid: Txid) -> anyhow::Result<Vec<ServerVtxo>> {
		let stmt = self.prepare_typed(
			"SELECT vtxo FROM vtxo WHERE vtxo_txid = $1",
			&[Type::TEXT],
		).await?;

		let rows = self.query(&stmt, &[&txid.to_string()]).await?;

		rows.iter().map(|row| Ok(ServerVtxo::deserialize(row.get("vtxo"))?)).collect()
	}

	/// Get all funding transaction txids that have vtxos not yet in the frontier.
	///
	/// TODO: remove this once all deployments have run with finish_round adding
	/// vtxos directly to the frontier. It is only called once at startup now.
	pub async fn get_unfrontiered_funding_txids(&self) -> anyhow::Result<Vec<Txid>> {
		let stmt = self.prepare("
			SELECT DISTINCT v.vtxo_txid
			FROM vtxo v
			JOIN virtual_transaction vt ON vt.txid = v.vtxo_txid AND vt.is_funding = true
			WHERE v.frontier_at IS NULL
		").await?;

		let rows = self.query(&stmt, &[]).await?;

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
		let stmt = self.prepare_typed("
			UPDATE vtxo SET confirmed_height = NULL, updated_at = NOW()
			WHERE confirmed_height > $1
		", &[Type::INT4]).await?;
		self.execute(&stmt, &[&(height as i32)]).await?;

		let stmt = self.prepare_typed("
			UPDATE vtxo
			SET onchain_spent_height = NULL, onchain_spent_txid = NULL, updated_at = NOW()
			WHERE onchain_spent_height > $1
		", &[Type::INT4]).await?;
		self.execute(&stmt, &[&(height as i32)]).await?;

		Ok(())
	}
}
