/// This module contains utilities to create
/// database queries.
///
/// This module does not create connections or
/// transactions. It is up to the user of this
/// module to create and commit transactions if
/// this is a requirement.

use std::borrow::Borrow;
use tokio_postgres::GenericClient;
use tokio_postgres::types::Type;

use ark::{Vtxo, ProtocolEncoding};

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
