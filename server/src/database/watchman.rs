
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
		", &[&funding_txid.to_string(), &confirmed_height.map(|h| h.to_u32() as i32)]).await?;

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

		self.execute(&stmt, &[&vtxo_id.to_string(), &(height.to_u32() as i32)]).await?;

		Ok(())
	}

	/// Clear the confirmation height of all vtxos created by a tx that is
	/// no longer confirmed.
	///
	/// Returns the cleared vtxos with their stale height.
	pub async fn clear_vtxo_confirmations_by_txid(
		&self,
		txid: Txid,
	) -> anyhow::Result<Vec<(VtxoId, BlockHeight)>> {
		// The self-join exposes the pre-update row to RETURNING.
		let stmt = self.prepare_typed("
			UPDATE vtxo v SET confirmed_height = NULL, updated_at = NOW()
			FROM vtxo old
			WHERE old.id = v.id AND v.vtxo_txid = $1 AND v.confirmed_height IS NOT NULL
			RETURNING v.vtxo_id, old.confirmed_height
		", &[Type::TEXT]).await?;

		let rows = self.query(&stmt, &[&txid.to_string()]).await?;

		rows.iter().map(|row| {
			let vtxo_id = row.get::<_, &str>("vtxo_id").parse()?;
			let height = row.get::<_, i32>("confirmed_height");
			Ok((vtxo_id, BlockHeight::from(height as u32)))
		}).collect()
	}

	/// Clear the on-chain spend of all vtxos spent by a tx that is no
	/// longer confirmed.
	///
	/// Returns each cleared vtxo with its confirmation height and its
	/// stale spend height.
	pub async fn clear_vtxo_spends_by_txid(
		&self,
		spending_txid: Txid,
	) -> anyhow::Result<Vec<(ServerVtxo, Option<BlockHeight>, BlockHeight)>> {
		// The self-join exposes the pre-update row to RETURNING.
		let stmt = self.prepare_typed("
			UPDATE vtxo v
			SET onchain_spent_height = NULL, onchain_spent_txid = NULL, updated_at = NOW()
			FROM vtxo old
			WHERE old.id = v.id AND v.onchain_spent_txid = $1
			RETURNING v.vtxo, v.confirmed_height, old.onchain_spent_height
		", &[Type::TEXT]).await?;

		let rows = self.query(&stmt, &[&spending_txid.to_string()]).await?;

		rows.iter().map(|row| {
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			let confirmed_height = row.get::<_, Option<i32>>("confirmed_height")
				.map(|h| BlockHeight::from(h as u32));
			let spent_height = row.get::<_, i32>("onchain_spent_height");
			Ok((vtxo, confirmed_height, BlockHeight::from(spent_height as u32)))
		}).collect()
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

		self.execute(&stmt, &[&vtxo_id.to_string(), &(height.to_u32() as i32), &txid.to_string()]).await?;

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
			let confirmed_height = confirmed_height.map(|h| {
				BlockHeight::try_from(h).expect("invalid block height in db")
			});
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			frontier.insert(vtxo.id(), (confirmed_height, vtxo));
		}

		Ok(frontier)
	}

	/// Get all vtxos that originate from a specific transaction, each with
	/// its recorded on-chain spend height and spending txid, if any.
	///
	/// Callers use this to register vtxos into the frontier; a vtxo with a
	/// recorded spend height was already advanced past and must not re-enter
	/// it. The spending txid can be absent even when the height is set: data
	/// repair writes a sentinel height without one (see fix_offboard_vtxos).
	pub async fn get_vtxos_by_txid(
		&self,
		txid: Txid,
	) -> anyhow::Result<Vec<(ServerVtxo, Option<BlockHeight>, Option<Txid>)>> {
		let stmt = self.prepare_typed(
			"SELECT vtxo, onchain_spent_height, onchain_spent_txid \
			FROM vtxo WHERE vtxo_txid = $1",
			&[Type::TEXT],
		).await?;

		let rows = self.query(&stmt, &[&txid.to_string()]).await?;

		rows.iter().map(|row| {
			let vtxo = ServerVtxo::deserialize(row.get("vtxo"))?;
			let spent_height: Option<i32> = row.get("onchain_spent_height");
			let spent_txid: Option<String> = row.get("onchain_spent_txid");
			let spent_txid = spent_txid.map(|t| t.parse()).transpose()?;
			Ok((vtxo, spent_height.map(|i| BlockHeight::from(i as u32)), spent_txid))
		}).collect()
	}

	/// Get all funding transaction txids that have vtxos not yet in the frontier.
	///
	/// Every code path that creates funding vtxos adds them to the frontier
	/// in the same database transaction, so this only finds legacy rows or
	/// rows left behind by a bug. It is only used by the frontier reindex.
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
		self.execute(&stmt, &[&(height.to_u32() as i32)]).await?;

		let stmt = self.prepare_typed("
			UPDATE vtxo
			SET onchain_spent_height = NULL, onchain_spent_txid = NULL, updated_at = NOW()
			WHERE onchain_spent_height > $1
		", &[Type::INT4]).await?;
		self.execute(&stmt, &[&(height.to_u32() as i32)]).await?;

		Ok(())
	}
}
