
use std::ops::Deref;

use futures::{Stream, TryStreamExt};
use postgres_types::Type;
use tokio_postgres::Row;
use ark::{ProtocolEncoding, Vtxo, VtxoId};

use crate::database::{Db, OwnedRowStream, NOARG};


/// A struct reprensenting a vtxo currently in the vtxo pool.
#[derive(Debug, Clone)]
pub struct PoolVtxo(Vtxo);

impl PoolVtxo {
	pub fn new(vtxo: Vtxo) -> Self {
		PoolVtxo(vtxo)
	}

	pub fn inner(&self) -> &Vtxo {
		&self.0
	}
}

impl Deref for PoolVtxo {
	type Target = Vtxo;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

impl TryFrom<Row> for PoolVtxo {
	type Error = anyhow::Error;

	fn try_from(row: Row) -> Result<Self, Self::Error> {
		Ok(PoolVtxo(Vtxo::deserialize(row.get("vtxo"))?))
	}
}

impl Db {
	pub async fn get_pool_vtxos_by_ids(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<PoolVtxo>> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed(
			"SELECT vtxo FROM vtxo_pool WHERE vtxo_id = ANY($1)",
			&[Type::TEXT_ARRAY],
		).await?;
		let rows = conn.query(&stmt, &[&ids.iter().map(|id| id.to_string()).collect::<Vec<_>>()]).await?;

		let mut vtxos = vec![];
		for row in rows {
			vtxos.push(PoolVtxo::try_from(row)?);
		}

		Ok(vtxos)
	}

	pub async fn store_vtxopool_vtxo(
		&self,
		vtxo: &PoolVtxo,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed(
			"INSERT INTO vtxo_pool (vtxo_id, vtxo, expiry_height, amount) \
				VALUES ( $1, $2, $3, $4)",
			&[Type::TEXT, Type::BYTEA, Type::INT4, Type::INT8],
		).await?;

		conn.execute(&stmt, &[
			&vtxo.id().to_string(),
			&vtxo.serialize(),
			&(vtxo.expiry_height() as i32),
			&(vtxo.amount().to_sat() as i64),
		]).await?;
		Ok(())
	}

	pub async fn store_vtxopool_vtxos<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a PoolVtxo>,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed(
			"INSERT INTO vtxo_pool (vtxo_id, vtxo, expiry_height, amount) \
				VALUES ( UNNEST($1), UNNEST($2), UNNEST($3), UNNEST($4) )",
			&[Type::TEXT_ARRAY, Type::BYTEA_ARRAY, Type::INT4_ARRAY, Type::INT8_ARRAY],
		).await?;

		let (ids, vtxos, expiries, amounts) = vtxos.into_iter().map(|v|
			(v.id().to_string(),
			v.serialize(),
			v.expiry_height() as i32,
			v.amount().to_sat() as i64,
		)).collect::<(Vec<_>, Vec<_>, Vec<_>, Vec<_>)>();

		conn.execute(&stmt, &[&ids, &vtxos, &expiries, &amounts]).await?;
		Ok(())
	}

	pub async fn mark_vtxopool_vtxos_spent(
		&self,
		ids: impl IntoIterator<Item = VtxoId>,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
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
		let conn = self.get_conn().await?;
		// fetch without keys
		let stmt = conn.prepare(
			"SELECT vtxo_id, vtxo, expiry_height, amount FROM vtxo_pool WHERE spent_at IS NULL",
		).await?;

		let rows = conn.query_raw(&stmt, NOARG).await?;
		let stream = OwnedRowStream::new(conn, rows);
		Ok(stream.err_into::<anyhow::Error>().and_then(
			|row| futures::future::ready(PoolVtxo::try_from(row))
		))
	}
}
