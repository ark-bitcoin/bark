/// This module contains utilities to create
/// database queries.
///
/// This module does not create connections or
/// transactions. It is up to the user of this
/// module to create and commit transactions if
/// this is a requirement.

use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::Context;
use tokio_postgres::GenericClient;
use tokio_postgres::types::Type;

use ark::{Vtxo, VtxoId, ProtocolEncoding};
use crate::database::model::VtxoState;

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
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, forfeit_state, forfeit_round_id,
			board_swept_at, created_at, updated_at
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

