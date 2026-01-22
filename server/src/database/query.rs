use std::borrow::Borrow;
/// This module contains utilities to create
/// database queries.
///
/// This module does not create connections or
/// transactions. It is up to the user of this
/// module to create a database connection or
/// transaction if that is required.

use std::collections::HashMap;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, Transaction, Txid};
use tokio_postgres::{GenericClient, Row, Transaction as PgTransaction};
use tokio_postgres::types::Type;

use ark::{ProtocolEncoding, VtxoId, VtxoRequest, ServerVtxo};
use ark::rounds::RoundId;
use ark::tree::signed::{UnlockHash, UnlockPreimage};
use bitcoin_ext::BlockHeight;

use crate::database::model::{Board, VirtualTransaction, VtxoState};
use crate::database::rounds::{StoredRoundInput, StoredRoundParticipation};
use crate::error::ContextExt;
use crate::secret::Secret;

pub async fn upsert_virtual_transaction<T: GenericClient>(
	client: &T,
	txid: Txid,
	signed_tx: Option<&Transaction>,
	is_funding: bool,
	server_may_own_descendant_since: Option<chrono::DateTime<chrono::Local>>,
) -> anyhow::Result<Txid> {
	let signed_tx_bytes = signed_tx.map(|tx| bitcoin::consensus::serialize(tx));

	client.execute("
		INSERT INTO virtual_transaction (txid, signed_tx, is_funding, server_may_own_descendant_since, created_at, updated_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (txid) DO UPDATE SET
			signed_tx = COALESCE(virtual_transaction.signed_tx, EXCLUDED.signed_tx),
			server_may_own_descendant_since = COALESCE(virtual_transaction.server_may_own_descendant_since, EXCLUDED.server_may_own_descendant_since),
			updated_at = NOW()
	", &[&txid.to_string(), &signed_tx_bytes, &is_funding, &server_may_own_descendant_since]).await
		.context("Failed to upsert virtual_transaction")?;

	Ok(txid)
}

pub async fn get_virtual_transaction_by_txid<T: GenericClient>(
	client: &T,
	txid: Txid,
) -> anyhow::Result<Option<VirtualTransaction<'static>>> {
	let stmt = client.prepare(
		"SELECT txid, signed_tx, is_funding, server_may_own_descendant_since
			FROM virtual_transaction
			WHERE txid = $1").await?;

	match client.query_opt(&stmt, &[&txid.to_string()]).await? {
		Some(row) => Ok(Some(VirtualTransaction::try_from(row)?)),
		None => Ok(None),
	}
}

/// Returns the first txid that exists in the virtual_transaction table but has no signed_tx.
/// Returns None if all txids either don't exist or are signed.
pub async fn get_first_unsigned_virtual_transaction<T: GenericClient>(
	client: &T,
	txids: &[Txid],
) -> anyhow::Result<Option<Txid>> {
	if txids.is_empty() {
		return Ok(None);
	}

	let txid_strings = txids.iter().map(|t| t.to_string()).collect::<Vec<_>>();
	let stmt = client.prepare_typed(
		"SELECT txid FROM virtual_transaction
			WHERE txid = ANY($1) AND signed_tx IS NULL
			LIMIT 1",
		&[Type::TEXT_ARRAY]
	).await?;

	match client.query_opt(&stmt, &[&txid_strings]).await? {
		Some(row) => {
			let txid_str: &str = row.get("txid");
			Ok(Some(Txid::from_str(txid_str).context("invalid txid in database")?))
		},
		None => Ok(None),
	}
}

pub async fn upsert_vtxos<T, V: Borrow<ServerVtxo>>(
	client: &T,
	vtxos: impl IntoIterator<Item = V>,
) -> Result<(), tokio_postgres::Error>
	where T: GenericClient
{
	let statement = client.prepare_typed("
		INSERT INTO vtxo (vtxo_id, vtxo_txid, vtxo, expiry, created_at, updated_at) VALUES (
			UNNEST($1), UNNEST($2), UNNEST($3), UNNEST($4), NOW(), NOW())
		ON CONFLICT DO NOTHING
	", &[Type::TEXT_ARRAY, Type::TEXT_ARRAY, Type::BYTEA_ARRAY, Type::INT4_ARRAY]).await?;

	let vtxos = vtxos.into_iter();
	let mut vtxo_ids = Vec::with_capacity(vtxos.size_hint().0);
	let mut vtxo_txids = Vec::with_capacity(vtxos.size_hint().0);
	let mut data = Vec::with_capacity(vtxos.size_hint().0);
	let mut expiry = Vec::with_capacity(vtxos.size_hint().0);
	for vtxo in vtxos {
		let vtxo = vtxo.borrow();
		vtxo_ids.push(vtxo.id().to_string());
		vtxo_txids.push(vtxo.point().txid.to_string());
		data.push(vtxo.serialize());
		expiry.push(vtxo.expiry_height() as i32);
	}

	client.execute(
		&statement,
		&[&vtxo_ids, &vtxo_txids, &data, &expiry]
	).await?;

	Ok(())
}

/// Get a VTXO by id
pub async fn get_vtxo_by_id<T>(client: &T, id: VtxoId) -> anyhow::Result<VtxoState>
	where T : GenericClient + Sized
{
	let stmt = client.prepare_typed("
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round, offboarded_in,
			created_at, updated_at
		FROM vtxo
		WHERE vtxo_id = $1;
	", &[Type::TEXT]).await?;

	let row = client.query_opt(&stmt, &[&id.to_string()]).await
		.context("Query get_vtxo_by_id failed")?
		.not_found([id], "VTXO not found")?;

	Ok(VtxoState::try_from(row)?)
}

/// Get vtxos by id and ensure the order of the returned vtxos matches
/// the order of the provided ids
pub async fn get_vtxos_by_id<T>(
	client: &T,
	ids: &[VtxoId],
) -> anyhow::Result<Vec<VtxoState>>
	where T: GenericClient + Sized
{
	let statement = client.prepare_typed("
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round, offboarded_in,
			created_at, updated_at
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

pub async fn store_round_participation(
	tx: &PgTransaction<'_>,
	unlock_hash: UnlockHash,
	unlock_preimage: UnlockPreimage,
	inputs: &[VtxoId],
	outputs: impl IntoIterator<Item = &VtxoRequest>,
) -> anyhow::Result<()> {
	let part_stmt = tx.prepare_typed(
		"INSERT INTO round_participation (unlock_hash, unlock_preimage, created_at) \
		VALUES ($1, $2, NOW()) RETURNING id",
		&[Type::TEXT, Type::BYTEA]
	).await?;

	let part_row = tx.query_one(&part_stmt, &[
		&unlock_hash.to_string(),
		&&unlock_preimage[..],
	]).await?;

	let part_id = part_row.get::<_, i64>("id");

	let input_stmt = tx.prepare_typed(
		"INSERT INTO round_part_input (participation_id, vtxo_id) VALUES ($1, $2)",
		&[Type::INT8, Type::TEXT]
	).await?;
	for input in inputs {
		tx.execute(&input_stmt, &[&part_id, &input.to_string()]).await?;
	}

	let output_stmt = tx.prepare_typed(
		"INSERT INTO round_part_output (participation_id, policy, amount) \
		VALUES ($1, $2, $3)",
		&[Type::INT8, Type::BYTEA, Type::INT8]
	).await?;

	for output in outputs {
		tx.execute(&output_stmt, &[
			&part_id,
			&output.policy.serialize(),
			&(output.amount.to_sat() as i64),
		]).await?;
	}

	Ok(())
}

/// complete a round participation from the main row
pub async fn complete_round_participation(
	tx: &PgTransaction<'_>,
	part_row: Row,
) -> anyhow::Result<StoredRoundParticipation> {
	let part_id = part_row.get::<_, i64>("id");

	let input_rows = tx.query(
		"SELECT vtxo_id, signed_forfeit_tx, signed_forfeit_claim_tx \
			FROM round_part_input WHERE participation_id = $1",
		&[&part_id],
	).await?;

	let mut inputs = Vec::with_capacity(input_rows.len());
	for row in input_rows {
		let signed_forfeit_tx = row.get::<_, Option<&[u8]>>("signed_forfeit_tx").map(|b|
			bitcoin::consensus::deserialize::<bitcoin::Transaction>(b)
				.context("invalid round input signed_forfeit_tx")
		).transpose()?;

		let signed_forfeit_claim_tx = row.get::<_, Option<&[u8]>>("signed_forfeit_claim_tx").map(|b|
			bitcoin::consensus::deserialize::<bitcoin::Transaction>(b)
				.context("invalid round input signed_forfeit_claim_tx")
		).transpose()?;

		inputs.push(StoredRoundInput {
			vtxo_id: VtxoId::from_str(&row.get::<_, &str>("vtxo_id"))
				.context("invalid round input vtxoid")?,
			signed_forfeit_tx,
			signed_forfeit_claim_tx,
		});
	}

	let output_rows = tx.query(
		"SELECT policy, amount FROM round_part_output WHERE participation_id = $1",
		&[&part_id],
	).await?;

	let mut outputs = Vec::with_capacity(output_rows.len());
	for row in output_rows {
		let policy_bytes = row.get::<_, &[u8]>("policy");
		let amount = row.get::<_, i64>("amount");
		outputs.push(VtxoRequest {
			policy: ark::VtxoPolicy::deserialize(policy_bytes)
				.context("invalid vtxo policy in round outputs")?,
			amount: Amount::from_sat(amount as u64),
		});
	}

	let round_id = part_row.get::<_, Option<&str>>("round_id").map(|id|
		RoundId::from_str(id).context("invalid round id")
	).transpose()?;

	let unlock_preimage = UnlockPreimage::try_from(part_row.get::<_, &[u8]>("unlock_preimage"))
		.context("invalid unlock_preimage")?;
	let unlock_hash = UnlockHash::from_str(&part_row.get::<_, &str>("unlock_hash"))
		.context("invalid unlock_hash")?;
	ensure!(UnlockHash::hash(&unlock_preimage) == unlock_hash,
		"unlock_hash ({}) does not match unlock_preimage ({})",
		unlock_hash, unlock_preimage.as_hex(),
	);

	Ok(StoredRoundParticipation {
		unlock_preimage: Secret::new(unlock_preimage),
		unlock_hash,
		inputs,
		outputs,
		round_id,
	})
}

pub async fn set_round_id_for_participations(
	tx: &PgTransaction<'_>,
	unlock_hashes: impl IntoIterator<Item = UnlockHash>,
	round_txid: Txid,
) -> anyhow::Result<()> {
	let unlock_hash_strings = unlock_hashes.into_iter()
		.map(|h| h.to_string())
		.collect::<Vec<_>>();

	if unlock_hash_strings.is_empty() {
		return Ok(());
	}

	let stmt = tx.prepare_typed(
		"UPDATE round_participation SET round_id = $1 WHERE unlock_hash = ANY($2)",
		&[Type::TEXT, Type::TEXT_ARRAY]
	).await?;
	tx.execute(&stmt, &[&round_txid.to_string(), &unlock_hash_strings]).await?;

	Ok(())
}
