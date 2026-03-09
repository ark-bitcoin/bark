use anyhow::Context;

use tokio_postgres::GenericClient;
use tokio_postgres::types::Type;

use ark::VtxoId;
use ark::ServerVtxoPolicy;
use ark::vtxo::Bare;

use bitcoin_ext::BlockHeight;

use super::Db;
use super::model::VtxoState;

/// Ban a vtxo until the given block height
pub async fn ban_vtxo<T: GenericClient>(
	client: &T,
	vtxo_id: VtxoId,
	until_height: BlockHeight,
) -> anyhow::Result<()> {
	let stmt = client.prepare_typed("
		UPDATE vtxo SET banned_until_height = $2, updated_at = NOW()
		WHERE vtxo_id = $1
	", &[Type::TEXT, Type::INT4]).await?;

	let rows = client.execute(&stmt, &[
		&vtxo_id.to_string(),
		&(until_height as i32),
	]).await.context("failed to ban vtxo")?;

	ensure!(rows > 0, "vtxo {} not found", vtxo_id);
	Ok(())
}

/// Remove the ban from a vtxo
pub async fn unban_vtxo<T: GenericClient>(
	client: &T,
	vtxo_id: VtxoId,
) -> anyhow::Result<()> {
	let stmt = client.prepare_typed("
		UPDATE vtxo SET banned_until_height = NULL, updated_at = NOW()
		WHERE vtxo_id = $1
	", &[Type::TEXT]).await?;

	let rows = client.execute(&stmt, &[
		&vtxo_id.to_string(),
	]).await.context("failed to unban vtxo")?;

	ensure!(rows > 0, "vtxo {} not found", vtxo_id);
	Ok(())
}

/// List all vtxos that are currently banned at the given chain tip.
pub async fn list_banned_vtxos<T: GenericClient>(
	client: &T,
	chain_tip: BlockHeight,
) -> anyhow::Result<Vec<VtxoState<Bare, ServerVtxoPolicy>>> {
	let stmt = client.prepare_typed("
		SELECT id, vtxo_id, expiry, exit_delta, policy_type, policy,
			server_pubkey, amount, anchor_point,
			oor_spent_txid, spent_in_round, offboarded_in,
			banned_until_height, created_at, updated_at
		FROM vtxo
		WHERE banned_until_height IS NOT NULL AND banned_until_height > $1
	", &[Type::INT4]).await?;

	let rows = client.query(&stmt, &[&(chain_tip as i32)]).await
		.context("failed to list banned vtxos")?;

	rows.into_iter()
		.map(|row| VtxoState::try_from(row))
		.collect()
}

impl Db {
	/// Ban a vtxo until a given block height
	pub async fn ban_vtxo(&self, vtxo_id: VtxoId, until_height: BlockHeight) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		ban_vtxo(&*conn, vtxo_id, until_height).await
	}

	/// Remove the ban from a vtxo
	pub async fn unban_vtxo(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		unban_vtxo(&*conn, vtxo_id).await
	}

	/// List all vtxos that are currently banned at the given chain tip.
	pub async fn list_banned_vtxos(&self, chain_tip: BlockHeight) -> anyhow::Result<Vec<VtxoState<Bare, ServerVtxoPolicy>>> {
		let conn = self.get_conn().await?;
		list_banned_vtxos(&*conn, chain_tip).await
	}
}
