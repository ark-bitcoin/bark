use std::borrow::Borrow;
use bitcoin::hex::FromHex;
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
use bitcoin::{Amount, Txid};
use tokio_postgres::{GenericClient, Row, Transaction as PgTransaction};
use tokio_postgres::types::Type;

use ark::{ProtocolEncoding, ServerVtxoPolicy, VtxoId, VtxoRequest};
use ark::mailbox::MailboxIdentifier;
use ark::rounds::RoundId;
use ark::tree::signed::{UnlockHash, UnlockPreimage};
use ark::vtxo::{Bare, Full};

use crate::database::model::{VirtualTransaction, VtxoState};
use crate::database::rounds::{StoredRoundInput, StoredRoundOutput, StoredRoundParticipation};
use crate::error::ContextExt;
use crate::secret::Secret;


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


/// Get a VTXO by id
///
/// This function returns a [ServerVtxo]
pub async fn get_vtxo_by_id<T>(
	client: &T,
	id: VtxoId,
) -> anyhow::Result<VtxoState<Full, ServerVtxoPolicy>>
	where T : GenericClient + Sized
{
	let stmt = client.prepare_typed("
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round, offboarded_in,
			banned_until_height, created_at, updated_at
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
///
/// This function returns [ServerVtxo]s
pub async fn get_vtxos_by_id<T>(
	client: &T,
	ids: &[VtxoId],
) -> anyhow::Result<Vec<VtxoState<Full, ServerVtxoPolicy>>>
	where T: GenericClient + Sized
{
	let statement = client.prepare_typed("
		SELECT id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round, offboarded_in,
			banned_until_height, created_at, updated_at
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

/// Get a bare VTXO by id, constructed from the metadata columns
/// without deserializing the full vtxo blob.
pub async fn get_bare_vtxo_by_id<T>(
	client: &T,
	id: VtxoId,
) -> anyhow::Result<VtxoState<Bare, ServerVtxoPolicy>>
	where T: GenericClient + Sized
{
	let stmt = client.prepare_typed("
		SELECT id, vtxo_id, expiry, exit_delta, policy_type, policy,
			server_pubkey, amount, anchor_point,
			oor_spent_txid, spent_in_round, offboarded_in,
			banned_until_height, created_at, updated_at
		FROM vtxo
		WHERE vtxo_id = $1;
	", &[Type::TEXT]).await?;

	let row = client.query_opt(&stmt, &[&id.to_string()]).await
		.context("Query get_bare_vtxo_by_id failed")?
		.not_found([id], "VTXO not found")?;

	Ok(VtxoState::try_from(row)?)
}

pub async fn store_round_participation(
	tx: &PgTransaction<'_>,
	unlock_hash: UnlockHash,
	unlock_preimage: UnlockPreimage,
	inputs: &[VtxoId],
	outputs: impl IntoIterator<Item = &StoredRoundOutput>,
) -> anyhow::Result<()> {
	let part_stmt = tx.prepare_typed(
		"INSERT INTO round_participation (unlock_hash, unlock_preimage, created_at) \
		VALUES ($1, $2, NOW()) RETURNING id",
		&[Type::TEXT, Type::TEXT]
	).await?;

	let part_row = tx.query_one(&part_stmt, &[
		&unlock_hash.to_string(),
		&unlock_preimage.to_lower_hex_string(),
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
		"INSERT INTO round_part_output (participation_id, policy, amount, unblinded_mailbox_id) \
		VALUES ($1, $2, $3, $4)",
		&[Type::INT8, Type::BYTEA, Type::INT8, Type::TEXT]
	).await?;

	for output in outputs {
		let unblinded_mailbox_id = output.unblinded_mailbox_id.map(|b| b.to_string());
		tx.execute(&output_stmt, &[
			&part_id,
			&output.vtxo_request.policy.serialize(),
			&(output.vtxo_request.amount.to_sat() as i64),
			&unblinded_mailbox_id,
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
		"SELECT vtxo_id, signed_forfeit_tx \
			FROM round_part_input WHERE participation_id = $1",
		&[&part_id],
	).await?;

	let mut inputs = Vec::with_capacity(input_rows.len());
	for row in input_rows {
		let signed_forfeit_tx = row.get::<_, Option<&[u8]>>("signed_forfeit_tx").map(|b|
			bitcoin::consensus::deserialize::<bitcoin::Transaction>(b)
				.context("invalid round input signed_forfeit_tx")
		).transpose()?;

		inputs.push(StoredRoundInput {
			vtxo_id: VtxoId::from_str(&row.get::<_, &str>("vtxo_id"))
				.context("invalid round input vtxoid")?,
			signed_forfeit_tx,
		});
	}

	let output_rows = tx.query(
		"SELECT policy, amount, unblinded_mailbox_id FROM round_part_output WHERE participation_id = $1",
		&[&part_id],
	).await?;

	let mut outputs = Vec::with_capacity(output_rows.len());
	for row in output_rows {
		let policy_bytes = row.get::<_, &[u8]>("policy");
		let amount = row.get::<_, i64>("amount");
		let unblinded_mailbox_id_str = row.get::<_, Option<&str>>("unblinded_mailbox_id");
		outputs.push(StoredRoundOutput {
			vtxo_request: VtxoRequest {
				policy: ark::VtxoPolicy::deserialize(policy_bytes)
					.context("invalid vtxo policy in round outputs")?,
				amount: Amount::from_sat(amount as u64),
			},
			unblinded_mailbox_id: unblinded_mailbox_id_str.map(|id| MailboxIdentifier::from_str(id))
				.transpose().context("invalid unblinded_mailbox_id in round outputs")?,
		});
	}

	let round_id = part_row.get::<_, Option<&str>>("round_id").map(|id|
		RoundId::from_str(id).context("invalid round id")
	).transpose()?;

	let unlock_preimage = UnlockPreimage::from_hex(part_row.get::<_, &str>("unlock_preimage"))
		.context("invalid unlock_preimage")?;
	let unlock_hash = UnlockHash::from_str(&part_row.get::<_, &str>("unlock_hash"))
		.context("invalid unlock_hash")?;
	ensure!(UnlockHash::hash(&unlock_preimage) == unlock_hash,
		"unlock_hash ({}) does not match unlock_preimage ({})",
		unlock_hash, unlock_preimage.as_hex(),
	);

	let forfeited_at = part_row.get::<_, Option<chrono::DateTime<chrono::Local>>>("forfeited_at");

	Ok(StoredRoundParticipation {
		unlock_preimage: Secret::new(unlock_preimage),
		unlock_hash,
		inputs,
		outputs,
		round_id,
		forfeited_at,
	})
}

/// Marks virtual transactions as having server-owned descendants.
///
/// This function:
/// 1. Fails if any of the txids don't exist in the database
/// 2. Fails if any of the txids have NULL signed_tx
/// 3. Updates server_may_own_descendant_since only where it's currently NULL
/// 4. Does not overwrite existing server_may_own_descendant_since values
///
/// Returns an error if any transaction doesn't exist or has NULL signed_tx.
pub async fn mark_server_may_own_descendants<C: GenericClient>(
	client: &C,
	txids: impl IntoIterator<Item = impl Borrow<Txid>>,
) -> anyhow::Result<()> {
	let txid_strings = txids.into_iter().map(|t| t.borrow().to_string()).collect::<Vec<_>>();

	if txid_strings.is_empty() {
		return Ok(());
	}

	// Check that all txids exist and have signed_tx set
	// Returns the first txid that either doesn't exist or has NULL signed_tx
	let stmt = client.prepare_typed("
		WITH input_txids AS (
			SELECT unnest($1::TEXT[]) AS txid
		)
		SELECT i.txid, vt.txid IS NOT NULL AS exists
		FROM input_txids i
		LEFT JOIN virtual_transaction vt ON i.txid = vt.txid
		WHERE vt.txid IS NULL OR vt.signed_tx IS NULL
		LIMIT 1
	", &[Type::TEXT_ARRAY]).await?;

	if let Some(row) = client.query_opt(&stmt, &[&txid_strings]).await? {
		let txid_str: &str = row.get("txid");
		let exists: bool = row.get("exists");
		let txid = Txid::from_str(txid_str).context("invalid txid")?;

		if !exists {
			// Transaction doesn't exist (LEFT JOIN returned NULL)
			bail!("Cannot mark server_may_own_descendants: transaction {} does not exist", txid);
		} else {
			// Transaction exists but has NULL signed_tx
			bail!("Cannot mark server_may_own_descendants: transaction {} has NULL signed_tx", txid);
		}
	}

	// Update server_may_own_descendant_since only where it's currently NULL
	let stmt = client.prepare_typed("
		UPDATE virtual_transaction
		SET server_may_own_descendant_since = NOW(), updated_at = NOW()
		WHERE txid = ANY($1) AND server_may_own_descendant_since IS NULL
	", &[Type::TEXT_ARRAY]).await?;

	client.execute(&stmt, &[&txid_strings]).await
		.context("Failed to mark server_may_own_descendants")?;

	Ok(())
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

