
use std::str::FromStr;

use bitcoin::Amount;
use futures::{Stream, TryStreamExt};
use postgres_types::Type;
use tokio_postgres::Row;

use ark::VtxoId;
use bitcoin_ext::BlockHeight;

use crate::database::{Db, NOARG};

pub struct PoolVtxo {
	pub vtxo: VtxoId,
	pub amount: Amount,
	pub expiry_height: BlockHeight,
	// NB can only be up until 2^15
	pub depth: u16,
}

impl TryFrom<Row> for PoolVtxo {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(PoolVtxo {
			vtxo: VtxoId::from_str(row.get("vtxo_id"))?,
			amount: Amount::from_sat(row.get::<_, i64>("amount") as u64),
			expiry_height: row.get::<_, i32>("expiry_height") as u32,
			depth: row.get::<_, i16>("depth") as u16,
		})
	}
}

impl Db {
	pub async fn store_vtxopool_vtxo(
		&self,
		vtxo: &PoolVtxo,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare_typed(
			"INSERT INTO vtxo_pool (vtxo_id, expiry_height, amount, depth) \
				VALUES ( $1, $2, $3, $4 )",
			&[Type::TEXT, Type::INT4, Type::INT8, Type::INT2],
		).await?;

		conn.execute(&stmt, &[
			&vtxo.vtxo.to_string(),
			&(vtxo.expiry_height as i32),
			&(vtxo.amount.to_sat() as i64),
			&(vtxo.depth as i16),
		]).await?;
		Ok(())
	}

	pub async fn store_vtxopool_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a PoolVtxo>,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare_typed(
			"INSERT INTO vtxo_pool (vtxo_id, expiry_height, amount, depth) \
				VALUES ( UNNEST($1), UNNEST($2), UNNEST($3), UNNEST($4) )",
			&[Type::TEXT_ARRAY, Type::INT4_ARRAY, Type::INT8_ARRAY, Type::INT2_ARRAY],
		).await?;

		let (ids, expiries, amounts, depths) = vtxos.into_iter().map(|v|
			(v.vtxo.to_string(), v.expiry_height as i32, v.amount.to_sat() as i64, v.depth as i16)
		).collect::<(Vec<_>, Vec<_>, Vec<_>, Vec<_>)>();

		conn.execute(&stmt, &[&ids, &expiries, &amounts, &depths]).await?;
		Ok(())
	}

	pub async fn mark_vtxopool_vtxos_spent(
		&self,
		ids: impl IntoIterator<Item = VtxoId>,
	) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare_typed(
			"UPDATE vtxo_pool SET spent_at = NOW() WHERE vtxo_id = ANY($1)",
			&[Type::TEXT_ARRAY],
		).await?;

		let ids = ids.into_iter().map(|id| id.to_string()).collect::<Vec<_>>();
		conn.execute(&stmt, &[&ids]).await?;
		Ok(())
	}

	pub async fn load_vtxopool(
		&self,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<PoolVtxo>> + '_> {
		let conn = self.pool.get().await?;
		// fetch without keys
		let stmt = conn.prepare(
			"SELECT vtxo_id, expiry_height, amount, depth FROM vtxo_pool WHERE spent_at IS NULL",
		).await?;

		Ok(conn.query_raw(&stmt, NOARG).await?
			.err_into::<anyhow::Error>()
			.and_then(|row| async { PoolVtxo::try_from(row) })
		)
	}
}
