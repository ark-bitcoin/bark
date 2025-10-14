/// This module contains utilities to create
/// database queries.
///
/// This module does not create connections or
/// transactions. It is up to the user of this
/// module to create a database connection or
/// transaction if that is required.

use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::Context;
use tokio_postgres::GenericClient;
use tokio_postgres::types::Type;

use bitcoin_ext::BlockHeight;
use ark::{Vtxo, VtxoId, ProtocolEncoding};
use crate::database::model::{VtxoState, Board};

pub async fn upsert_vtxos<T, V: Borrow<Vtxo>>(
	client: &T,
	vtxos: impl IntoIterator<Item = V>,
) -> Result<(), tokio_postgres::Error>
	where T: GenericClient
{
	// Store all vtxos created in this round.
	let statement = client.prepare_typed("
		INSERT INTO vtxo (vtxo_id, vtxo, expiry, created_at, updated_at) VALUES (
			UNNEST($1), UNNEST($2), UNNEST($3), NOW(), NOW())
		ON CONFLICT DO NOTHING
	", &[Type::TEXT_ARRAY, Type::BYTEA_ARRAY, Type::INT4_ARRAY]).await?;

	let vtxos = vtxos.into_iter();
	let mut vtxo_ids = Vec::with_capacity(vtxos.size_hint().0);
	let mut data = Vec::with_capacity(vtxos.size_hint().0);
	let mut expiry = Vec::with_capacity(vtxos.size_hint().0);
	for vtxo in vtxos {
		let vtxo = vtxo.borrow();
		vtxo_ids.push(vtxo.id().to_string());
		data.push(vtxo.serialize());
		expiry.push(vtxo.expiry_height() as i32);
	}

	client.execute(
		&statement,
		&[&vtxo_ids, &data, &expiry]
	).await?;

	Ok(())
}


/// Get vtxos by id and ensure the order of the returned vtxos matches
/// the order of the provided ids
pub async fn get_vtxos_by_id<T>(
	client: &T,
	ids: &[VtxoId],
) -> anyhow::Result<Vec<VtxoState>>
	where T : GenericClient + Sized
{
	let statement = client.prepare_typed("
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, forfeit_state, forfeit_round_id, created_at, updated_at
		FROM vtxo
		WHERE vtxo_id = ANY($1);
	", &[Type::TEXT_ARRAY]).await?;

	let id_str = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
	let rows = client.query(&statement, &[&id_str]).await
		.context("Query get_vtxos_by_id failed")?;

	// Parse all rows
	let mut vtxos = rows.into_iter()
		.map(|row| {
			let vtxo = VtxoState::try_from(row)?;
			Ok((vtxo.vtxo.id(), vtxo))
		})
		.collect::<anyhow::Result<HashMap<_, _>>>()
		.context("Failed to parse VtxoState from database")?;

	// Bail if one of the id's could not be found
	if vtxos.len() != ids.len() {
		let missing = ids.into_iter().filter(|id| !vtxos.contains_key(id));
		return not_found!(missing, "vtxo does not exist");
	}

	Ok(ids.iter().map(|id| vtxos.remove(id).unwrap()).collect())
}

/// Upsert a board into the database
pub async fn upsert_board<T>(
	client: &T,
	vtxo_id: VtxoId,
	expiry_height: BlockHeight,
) -> anyhow::Result<Board>
	where T : GenericClient
{
	let statement = client.prepare("
		WITH INSERTED AS (
			INSERT INTO board (vtxo_id, expiry_height, created_at, updated_at)
			VALUES ($1, $2, NOW(), NOW())
			ON CONFLICT DO NOTHING
			RETURNING *
		)
		SELECT * FROM INSERTED
		UNION ALL
		SELECT * FROM board where vtxo_id = $1
		LIMIT 1;
	").await?;

	let row = client.query_one(&statement, &[&vtxo_id.to_string(), &(expiry_height as i32)]).await
		.context("Failed to execute query")?;

	Ok(Board::try_from(row)
		.context("Bad row: not a valid Board")?
	)
}

pub async fn get_sweepable_boards<T>(
	client: &T,
	height: BlockHeight,
) -> anyhow::Result<Vec<Board>>
	where T : GenericClient
{
	let statement = client.prepare("
		SELECT * FROM board WHERE expiry_height <= $1 AND swept_at IS NULL AND EXITED_at IS NULL;
	").await?;

	let rows = client.query(&statement, &[&(height as i32)]).await
		.context("Failed to execute `get_sweepable_boards` query")?;

	Ok(rows.into_iter().map(|row| Board::try_from(row)).collect::<anyhow::Result<Vec<_>>>()?)
}

pub async fn mark_board_swept<T>(
	client: &T,
	vtxo_id: VtxoId,
) -> anyhow::Result<()>
	where T : GenericClient
{
	let statement = client.prepare("
		UPDATE board SET swept_at = NOW(), updated_at = NOW() WHERE vtxo_id = $1 and swept_at IS NULL;
	").await?;

	client.execute(&statement, &[&vtxo_id.to_string()]).await
		.context("Failed to execute query")?;

	Ok(())
}