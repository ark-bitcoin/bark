use std::collections::HashMap;
use std::str::FromStr;

use anyhow::{Context, ensure};
use bitcoin::{Amount, Network, SignedAmount, Txid};
use bitcoin::consensus;
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use chrono::DateTime;
use lightning_invoice::Bolt11Invoice;
use rusqlite::{self, named_params, params, Connection, OptionalExtension, ToSql, Transaction};

use ark::{ProtocolEncoding, Vtxo};
use ark::lightning::{PaymentHash, Preimage};
use ark::vtxo::Full;

use crate::{VtxoId, WalletProperties};
use crate::actions::{WalletActionCheckpoint, WalletActionId};
use crate::exit::{ExitState, ExitTxOrigin};
use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem, PaymentMethod};
use crate::persist::{RoundStateId, StoredRoundState};
use crate::persist::models::{
	PaidInvoice, SerdeRoundState, SettledLightningReceive,
	StoredExit, Unlocked, PendingOffboard,
};
use crate::persist::sqlite::convert::{row_to_movement, row_to_wallet_vtxo, rows_to_wallet_vtxos};
use crate::round::RoundState;
use crate::vtxo::{VtxoState, VtxoStateKind, WalletVtxo};

/// Set read-only properties for the wallet
///
/// This is fail if properties aren't already set for the wallet
pub (crate) fn set_properties(
	conn: &Connection,
	properties: &WalletProperties,
) -> anyhow::Result<()> {
	let query =
		"INSERT INTO bark_properties (id, network, fingerprint, server_pubkey, server_mailbox_pubkey)
		VALUES (1, :network, :fingerprint, :server_pubkey, :server_mailbox_pubkey)";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":network": properties.network.to_string(),
		":fingerprint": properties.fingerprint.to_string(),
		":server_pubkey": properties.server_pubkey.map(|pk| pk.to_string()),
		":server_mailbox_pubkey": properties.server_mailbox_pubkey.map(|pk| pk.to_string()),
	})?;

	Ok(())
}

/// Update the server pubkey in the wallet properties.
///
/// This is used when an existing wallet first connects to a server after
/// the server pubkey tracking was added.
pub (crate) fn set_server_pubkey(
	conn: &Connection,
	server_pubkey: &PublicKey,
) -> anyhow::Result<()> {
	let query = "UPDATE bark_properties SET server_pubkey = :server_pubkey
		WHERE id = 1 AND server_pubkey IS NULL";
	let mut statement = conn.prepare(query)?;

	let rows = statement.execute(named_params! {
		":server_pubkey": server_pubkey.to_string(),
	})?;
	ensure!(rows == 1, "failed to store server pubkey: \
		expected 1 row updated, got {rows} (already set?)");

	Ok(())
}

pub (crate) fn set_server_mailbox_pubkey(
	conn: &Connection,
	server_mailbox_pubkey: &PublicKey,
) -> anyhow::Result<()> {
	let query = "UPDATE bark_properties SET server_mailbox_pubkey = :server_mailbox_pubkey
		WHERE id = 1 AND server_mailbox_pubkey IS NULL";
	let mut statement = conn.prepare(query)?;

	let rows = statement.execute(named_params! {
		":server_mailbox_pubkey": server_mailbox_pubkey.to_string(),
	})?;
	ensure!(rows == 1, "failed to store server mailbox pubkey: \
		expected 1 row updated, got {rows} (already set?)");

	Ok(())
}

pub (crate) fn fetch_properties(conn: &Connection) -> anyhow::Result<Option<WalletProperties>> {
	let query = "SELECT * FROM bark_properties";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let network: String = row.get("network")?;
		let fingerprint: String = row.get("fingerprint")?;
		let server_pubkey: Option<String> = row.get("server_pubkey")?;
		let server_mailbox_pubkey: Option<String> = row.get("server_mailbox_pubkey")?;

		let server_pubkey = server_pubkey
			.map(|s| PublicKey::from_str(&s))
			.transpose()
			.context("invalid server pubkey")?;

		let server_mailbox_pubkey = server_mailbox_pubkey
			.map(|s| PublicKey::from_str(&s))
			.transpose()
			.context("invalid server mailbox pubkey")?;

		Ok(Some(
			WalletProperties {
				network: Network::from_str(&network).context("invalid network")?,
				fingerprint: Fingerprint::from_str(&fingerprint).context("invalid fingerprint")?,
				server_pubkey,
				server_mailbox_pubkey,
			}
		))
	} else {
		Ok(None)
	}
}

pub fn create_new_movement(
	tx: &Transaction,
	status: MovementStatus,
	subsystem: &MovementSubsystem,
	time: DateTime<chrono::Local>,
	action_id: Option<&str>,
) -> anyhow::Result<MovementId> {
	let mut statement = tx.prepare("
		INSERT INTO bark_movements (status, subsystem_name, movement_kind, intended_balance,
			effective_balance, offchain_fee, created_at, updated_at, action_id)
		VALUES (:status, :name, :kind, :intended_balance, :effective_balance, :offchain_fee,
			:created_at, :updated_at, :action_id)
		RETURNING id"
	)?;
	let time = time.with_timezone(&chrono::Utc);
	let id = statement.query_row(named_params! {
		":status": status.as_str(),
		":name": subsystem.name,
		":kind": subsystem.kind,
		":intended_balance": SignedAmount::ZERO.to_sat(),
		":effective_balance": SignedAmount::ZERO.to_sat(),
		":offchain_fee": Amount::ZERO.to_sat(),
		":created_at": time,
		":updated_at": time,
		":action_id": action_id,
	}, |row| row.get::<_, u32>(0))?;

	Ok(MovementId::new(id))
}

pub fn get_movement_id_by_action(
	tx: &Transaction,
	action_id: &str,
) -> anyhow::Result<Option<MovementId>> {
	let mut statement = tx.prepare(
		"SELECT id FROM bark_movements WHERE action_id = ?1"
	)?;
	let id = statement.query_row([action_id], |row| row.get::<_, u32>(0))
		.optional()?;
	Ok(id.map(MovementId::new))
}

pub fn update_movement(tx: &Transaction, movement: &Movement) -> anyhow::Result<()> {
	let id = movement.id.0;
	tx.execute(
		"UPDATE bark_movements
		SET status = :status, metadata = :metadata, intended_balance = :intended,
			effective_balance = :effective, offchain_fee = :offchain_fee, updated_at = :updated_at,
			completed_at = :completed_at
		WHERE id = :id",
		named_params! {
			":id": id,
			":status": movement.status.as_str(),
			":metadata": serde_json::to_string(&movement.metadata)?,
			":intended": movement.intended_balance.to_sat(),
			":effective": movement.effective_balance.to_sat(),
			":offchain_fee": movement.offchain_fee.to_sat(),
			":updated_at": movement.time.updated_at.with_timezone(&chrono::Utc),
			":completed_at": movement.time.completed_at.map(|t| t.with_timezone(&chrono::Utc)),
		},
	)?;
	// Update the recipient tables
	let recipient_updates = [
		("bark_movements_sent_to", &movement.sent_to),
		("bark_movements_received_on", &movement.received_on),
	];
	for (table, vec) in recipient_updates {
		tx.execute(&format!("DELETE FROM {} WHERE movement_id = ?1", table), params![id])?;
		for dest in vec {
			tx.execute(
				&format!(
					"INSERT INTO {} (movement_id, destination_type, destination_value, amount) \
					VALUES (?1, ?2, ?3, ?4)",
					table,
				),
				params![
					id,
					dest.destination.type_str(),
					&dest.destination.value_string(),
					dest.amount.to_sat(),
				],
			)?;
		}
	}
	// Update the VTXO tables
	let vtxo_updates = [
		("bark_movements_input_vtxos", &movement.input_vtxos),
		("bark_movements_output_vtxos", &movement.output_vtxos),
		("bark_movements_exited_vtxos", &movement.exited_vtxos),
	];
	for (table, vec) in vtxo_updates {
		tx.execute(&format!("DELETE FROM {} WHERE movement_id = ?1", table), params![id])?;
		for vtxo_id in vec {
			tx.execute(
				&format!("INSERT INTO {} (movement_id, vtxo_id) VALUES (?1, ?2)", table),
				params![id, vtxo_id.to_string()],
			)?;
		}
	}
	Ok(())
}

pub fn get_all_movements(conn: &Connection) -> anyhow::Result<Vec<Movement>> {
	let mut statement = conn.prepare(
		"SELECT * FROM bark_movements_view ORDER BY created_at DESC, id DESC",
	)?;
	let mut rows = statement.query([])?;
	let mut results = Vec::new();
	while let Some(row) = rows.next()? {
		results.push(row_to_movement(row)?);
	}
	Ok(results)
}

pub fn get_movement_by_id(conn: &Connection, id: MovementId) -> anyhow::Result<Movement> {
	let mut statement = conn.prepare(
		"SELECT * FROM bark_movements_view WHERE id = ?1"
	)?;
	let mut rows = statement.query([id.0])?;
	if let Some(row) = rows.next()? {
		Ok(row_to_movement(row)?)
	} else {
		Err(anyhow!("Movement {} not found", id))
	}
}

pub fn get_movements_by_payment_method(
	conn: &Connection,
	payment_method: &PaymentMethod,
) -> anyhow::Result<Vec<Movement>> {
	let mut statement = conn.prepare(
		"SELECT mv.* FROM bark_movements_view mv
		WHERE mv.id IN (
			SELECT movement_id FROM bark_movements_sent_to
				WHERE destination_type = ?1 AND destination_value = ?2
			UNION
			SELECT movement_id FROM bark_movements_received_on
				WHERE destination_type = ?1 AND destination_value = ?2
		);"
	)?;
	let pm = payment_method.value_string();
	let mut rows = statement.query(&[payment_method.type_str(), &pm])?;
	let mut results = Vec::new();
	while let Some(row) = rows.next()? {
		results.push(row_to_movement(row)?);
	}
	Ok(results)
}

pub fn store_pending_offboard(
	tx: &Transaction,
	pending: &PendingOffboard,
) -> anyhow::Result<()> {
	let vtxo_ids_json = serde_json::to_string(&pending.vtxo_ids)
		.context("failed to serialize vtxo_ids")?;
	let offboard_tx_bytes = consensus::serialize(&pending.offboard_tx);

	let mut statement = tx.prepare("
		INSERT INTO bark_pending_offboard (movement_id, offboard_txid, offboard_tx, vtxo_ids, destination)
		VALUES (:movement_id, :offboard_txid, :offboard_tx, :vtxo_ids, :destination);"
	)?;

	statement.execute(named_params! {
		":movement_id": pending.movement_id.0,
		":offboard_txid": pending.offboard_txid.to_string(),
		":offboard_tx": offboard_tx_bytes,
		":vtxo_ids": vtxo_ids_json,
		":destination": pending.destination,
	})?;
	Ok(())
}

pub fn get_all_pending_offboards(conn: &Connection) -> anyhow::Result<Vec<PendingOffboard>> {
	let q = "SELECT movement_id, offboard_txid, offboard_tx, vtxo_ids, destination, created_at FROM bark_pending_offboard;";
	let mut statement = conn.prepare(q)?;
	let mut rows = statement.query([])?;
	let mut pending = Vec::new();
	while let Some(row) = rows.next()? {
		let movement_id = MovementId::new(row.get::<_, u32>("movement_id")?);
		let offboard_txid = Txid::from_str(&row.get::<_, String>("offboard_txid")?)?;
		let offboard_tx_bytes = row.get::<_, Vec<u8>>("offboard_tx")?;
		let offboard_tx: bitcoin::Transaction = consensus::deserialize(&offboard_tx_bytes)
			.context("failed to deserialize offboard_tx")?;
		let vtxo_ids_json = row.get::<_, String>("vtxo_ids")?;
		let vtxo_ids: Vec<VtxoId> = serde_json::from_str(&vtxo_ids_json)
			.context("failed to deserialize vtxo_ids")?;
		let destination = row.get::<_, String>("destination")?;
		let created_at = row.get::<_, DateTime<chrono::Utc>>("created_at")?
			.with_timezone(&chrono::Local);

		pending.push(PendingOffboard {
			movement_id,
			offboard_txid,
			offboard_tx,
			vtxo_ids,
			destination,
			created_at,
		});
	}
	Ok(pending)
}

pub fn remove_pending_offboard(
	tx: &Transaction,
	movement_id: MovementId,
) -> anyhow::Result<()> {
	let q = "DELETE FROM bark_pending_offboard WHERE movement_id = :movement_id;";
	let mut statement = tx.prepare(q)?;
	statement.execute(named_params! {
		":movement_id": movement_id.0,
	})?;
	Ok(())
}

pub fn store_vtxo_with_initial_state(
	tx: &Transaction,
	vtxo: &Vtxo<Full>,
	state: &VtxoState,
) -> anyhow::Result<()> {
	// Split the vtxo into bare bytes + genesis bytes, and precompute the
	// genesis-derived summaries that listings/refresh-strategy will need
	// without loading the genesis again.
	let raw_bare = vtxo.to_bare().serialize();
	let raw_genesis = vtxo.serialize_genesis();
	let exit_depth = vtxo.exit_depth() as i64;
	let exit_tx_weight = vtxo.transactions()
		.map(|t| t.tx.weight().to_wu())
		.sum::<u64>() as i64;

	// Store the vtxo, ignoring if it already exists (idempotent)
	let q1 =
		"INSERT OR IGNORE INTO bark_vtxo (
			id, expiry_height, amount_sat,
			raw_bare, raw_genesis, exit_depth, exit_tx_weight
		)
		VALUES (
			:vtxo_id, :expiry_height, :amount_sat,
			:raw_bare, :raw_genesis, :exit_depth, :exit_tx_weight
		);";
	let mut statement = tx.prepare(q1)?;
	let rows_inserted = statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.expiry_height(),
		":amount_sat": vtxo.amount().to_sat(),
		":raw_bare": raw_bare,
		":raw_genesis": raw_genesis,
		":exit_depth": exit_depth,
		":exit_tx_weight": exit_tx_weight,
	})?;

	// Only store initial state if vtxo was newly inserted.
	// If rows_inserted == 0, the vtxo already existed and has its state.
	if rows_inserted > 0 {
		let q2 =
			"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
			VALUES (:vtxo_id, :state_kind, :state);";
		let mut statement = tx.prepare(q2)?;
		statement.execute(named_params! {
			":vtxo_id": vtxo.id().to_string(),
			":state_kind": state.kind().as_str(),
			":state": serde_json::to_vec(&state)?,
		})?;
	}

	Ok(())
}

pub fn store_round_state(
	conn: &Connection,
	state: &RoundState,
) -> anyhow::Result<RoundStateId> {
	let bytes = rmp_serde::to_vec(&SerdeRoundState::from(state)).expect("can serialize");
	let mut stmt = conn.prepare(
		"INSERT INTO bark_round_state (state) VALUES (:state) RETURNING id",
	)?;
	let id = stmt.query_row(named_params! {
		":state": bytes,
	}, |row| row.get::<_, i64>(0))?;
	Ok(RoundStateId(id as u32))
}

pub fn update_round_state(
	conn: &Connection,
	state: &StoredRoundState,
) -> anyhow::Result<()> {
	let bytes = rmp_serde::to_vec(&SerdeRoundState::from(state.state())).expect("can serialize");
	let mut stmt = conn.prepare(
		"UPDATE bark_round_state SET state = :state WHERE id = :id",
	)?;
	stmt.execute(named_params! {
		":id": state.id().0 as i64,
		":state": bytes,
	})?;
	Ok(())
}

pub fn remove_round_state(
	conn: &Connection,
	id: RoundStateId,
) -> anyhow::Result<()> {
	let mut stmt = conn.prepare(
		"DELETE FROM bark_round_state WHERE id = :id",
	)?;
	stmt.execute(named_params! {
		":id": id.0 as i64,
	})?;
	Ok(())
}

pub fn get_round_state_by_id(
	conn: &Connection,
	id: RoundStateId,
) -> anyhow::Result<Option<StoredRoundState<Unlocked>>> {
	let mut stmt = conn.prepare("SELECT id, state FROM bark_round_state WHERE id = :id")?;
	let mut rows = stmt.query(named_params! {
		":id": id.0 as i64,
	})?;

	match rows.next()? {
		Some(row) => {
			let state = rmp_serde::from_slice::<SerdeRoundState>(&row.get::<_, Vec<u8>>(1)?)?;
			let id = RoundStateId(row.get::<_, i64>(0)? as u32);
			Ok(Some(StoredRoundState::new(id, state.into())))
		},
		None => Ok(None),
	}
}

pub fn get_pending_round_state_ids(
	conn: &Connection,
) -> anyhow::Result<Vec<RoundStateId>> {
	let mut stmt = conn.prepare("SELECT id FROM bark_round_state")?;
	let mut rows = stmt.query([])?;

	let mut ret = Vec::new();
	while let Some(row) = rows.next()? {
		ret.push(RoundStateId(row.get::<_, i64>(0)? as u32));
	}
	Ok(ret)
}

/// Columns the `vtxo_view`-based listings always select, in the order
/// [`row_to_wallet_vtxo`] expects them.
const VTXO_VIEW_COLUMNS: &str =
	"raw_bare, exit_depth, exit_tx_weight, state";

pub fn get_wallet_vtxo_by_id(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<WalletVtxo>> {
	let query = format!(
		"SELECT {VTXO_VIEW_COLUMNS} FROM vtxo_view WHERE id = ?1",
	);
	let mut statement = conn.prepare(&query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		Ok(Some(row_to_wallet_vtxo(&row)?))
	} else {
		Ok(None)
	}
}

pub fn get_all_vtxos(conn: &Connection) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = format!(
		"SELECT {VTXO_VIEW_COLUMNS}
		FROM vtxo_view
		ORDER BY expiry_height ASC, amount_sat DESC",
	);

	let mut statement = conn.prepare(&query)?;
	let rows = statement.query(())?;

	rows_to_wallet_vtxos(rows)
}

pub fn get_vtxos_by_state(
	conn: &Connection,
	state: &[VtxoStateKind]
) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = format!(
		"SELECT {VTXO_VIEW_COLUMNS}
		FROM vtxo_view
		WHERE state_kind IN (SELECT atom FROM json_each(?))
		ORDER BY expiry_height ASC, amount_sat DESC",
	);

	let mut statement = conn.prepare(&query)?;
	let rows = statement.query(&[&serde_json::to_string(&state)?])?;

	rows_to_wallet_vtxos(rows)
}

/// Hydrate a single VTXO into its full form (with the genesis chain), reading
/// from `bark_vtxo` directly. Returns `None` when no row exists.
pub fn get_full_vtxo_by_id(
	conn: &Connection,
	id: VtxoId,
) -> anyhow::Result<Option<Vtxo<Full>>> {
	let mut statement = conn.prepare(
		"SELECT raw_bare, raw_genesis FROM bark_vtxo WHERE id = ?1",
	)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let raw_bare: Vec<u8> = row.get(0)?;
		let raw_genesis: Vec<u8> = row.get(1)?;
		Ok(Some(reassemble_full_vtxo(&raw_bare, &raw_genesis)?))
	} else {
		Ok(None)
	}
}

/// Hydrate a batch of VTXOs by id, preserving the order of the input slice.
/// Errors if any id is missing — callers always come here from a selection
/// step against `vtxo_view`, so missing rows indicate the wallet's state is
/// inconsistent with what the caller just observed.
pub fn get_full_vtxos_by_ids(
	conn: &Connection,
	ids: &[VtxoId],
) -> anyhow::Result<Vec<Vtxo<Full>>> {
	if ids.is_empty() {
		return Ok(Vec::new());
	}

	let id_strings: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
	let mut statement = conn.prepare(
		"SELECT id, raw_bare, raw_genesis
		FROM bark_vtxo
		WHERE id IN (SELECT atom FROM json_each(?))",
	)?;

	let json_ids = serde_json::to_string(&id_strings)?;
	let rows = statement.query_map([json_ids], |row| {
		let id: String = row.get(0)?;
		let raw_bare: Vec<u8> = row.get(1)?;
		let raw_genesis: Vec<u8> = row.get(2)?;
		Ok((id, raw_bare, raw_genesis))
	})?;

	let mut by_id = HashMap::with_capacity(ids.len());
	for row in rows {
		let (id, raw_bare, raw_genesis) = row?;
		by_id.insert(id, reassemble_full_vtxo(&raw_bare, &raw_genesis)?);
	}

	let mut out = Vec::with_capacity(ids.len());
	for (id, id_str) in ids.iter().zip(id_strings.iter()) {
		match by_id.remove(id_str) {
			Some(v) => out.push(v),
			None => bail!("vtxo {id} not found in bark_vtxo"),
		}
	}
	Ok(out)
}

fn reassemble_full_vtxo(raw_bare: &[u8], raw_genesis: &[u8]) -> anyhow::Result<Vtxo<Full>> {
	Vtxo::<Full>::deserialize_with_genesis(raw_bare, raw_genesis).context("failed to load VTXO")
}

pub fn delete_vtxo(
	tx: &rusqlite::Transaction,
	id: VtxoId
) -> anyhow::Result<Option<Vtxo<Full>>> {
	// Delete all vtxo-states
	let query = "DELETE FROM bark_vtxo_state WHERE vtxo_id = ?1";
	tx.execute(query, [id.to_string()])?;

	let query = "DELETE FROM bark_vtxo WHERE id = ?1 RETURNING raw_bare, raw_genesis";
	let mut statement = tx.prepare(query)?;

	let vtxo = statement
		.query_and_then(
			[id.to_string()],
			|row| -> anyhow::Result<Vtxo<Full>> {
				let raw_bare: Vec<u8> = row.get(0)?;
				let raw_genesis: Vec<u8> = row.get(1)?;
				reassemble_full_vtxo(&raw_bare, &raw_genesis)
			})?
		.filter_map(|x| x.ok())
		.next();

	Ok(vtxo)
}

pub fn get_vtxo_state(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<VtxoState>> {
	let query =
		"SELECT state
		FROM bark_vtxo_state
		WHERE vtxo_id = ?1
		ORDER BY created_at DESC LIMIT 1";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let state = row.get::<_, Vec<u8>>(0)?;
		Ok(Some(serde_json::from_slice(&state)?))
	} else {
		Ok(None)
	}
}

/// Updates the state of a VTXO from one of the
/// values in `old_state` to `new_state`.
///
/// The method is atomic. If another process tries
/// to update the state only one of them will succeed.
///
/// If an error is reported the state will remain unchanged.
pub fn update_vtxo_state_checked(
	conn: &Connection,
	vtxo_id: VtxoId,
	new_state: VtxoState,
	old_states: &[VtxoStateKind],
) -> anyhow::Result<WalletVtxo> {
	let query = r"
		INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
		SELECT :vtxo_id, :state_kind, :state FROM most_recent_vtxo_state
		WHERE
			vtxo_id = :vtxo_id AND
			state_kind IN (SELECT atom FROM json_each(:old_states)) AND
			state != :state";

	let new_state_blob = serde_json::to_vec(&new_state)?;
	let mut statement = conn.prepare(query)?;
	let nb_inserted = statement.execute(named_params! {
		":vtxo_id": vtxo_id.to_string(),
		":state_kind": new_state.kind().as_str(),
		":state": &new_state_blob,
		":old_states": &serde_json::to_string(old_states)?,
	})?;

	match nb_inserted {
		0 => {
			match get_wallet_vtxo_by_id(conn, vtxo_id)? {
				Some(wv) if wv.state == new_state => Ok(wv),
				Some(wv) => bail!(
					"vtxo {} is in state {} which is not in the allowed old states {:?}",
					vtxo_id, wv.state.kind(), old_states,
				),
				None => bail!("no vtxo found with id {}", vtxo_id),
			}
		},
		1 => {
			get_wallet_vtxo_by_id(conn, vtxo_id)?
				.context("vtxo not found after state insert")
		},
		n => bail!("Corrupted database: inserted {n} state rows for a single vtxo"),
	}
}

/// Apply [update_vtxo_state_checked] to every id in `vtxo_ids` against the
/// same connection. The caller is expected to wrap this in a transaction
/// (BEGIN IMMEDIATE/COMMIT) so the batch is atomic and serialized against
/// concurrent writers.
pub fn update_vtxo_states_checked(
	conn: &Connection,
	vtxo_ids: &[VtxoId],
	new_state: VtxoState,
	old_states: &[VtxoStateKind],
) -> anyhow::Result<()> {
	for id in vtxo_ids {
		update_vtxo_state_checked(conn, *id, new_state.clone(), old_states)?;
	}
	Ok(())
}

pub fn store_vtxo_key(
	conn: &Connection,
	index: u32,
	public_key: PublicKey
) -> anyhow::Result<()> {
	let query = "INSERT INTO bark_vtxo_key (idx, public_key) VALUES (?1, ?2);";
	let mut statement = conn.prepare(query)?;
	statement.execute([index.to_sql()?, public_key.to_string().to_sql()?])?;
	Ok(())
}

pub fn get_public_key_idx(conn: &Connection, public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
	let query = "SELECT idx FROM bark_vtxo_key WHERE public_key = (?1)";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((public_key.to_string(), ))?;

	if let Some(row) = rows.next()? {
		Ok(Some(u32::try_from(row.get::<_, i64>("idx")?)?))
	} else {
		Ok(None)
	}
}

pub fn get_last_vtxo_key_index(conn: &Connection) -> anyhow::Result<Option<u32>> {
	let query = "SELECT idx FROM bark_vtxo_key ORDER BY idx DESC LIMIT 1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(())?;

	if let Some(row) = rows.next()? {
		Ok(Some(u32::try_from(row.get::<usize, i64>(0)?)?))
	} else {
		Ok(None)
	}
}

pub fn get_mailbox_checkpoint(conn: &Connection) -> anyhow::Result<u64> {
	let query = "SELECT checkpoint FROM bark_mailbox_checkpoint WHERE id = 1";

	let mut statement = conn.prepare(query)?;
	let cp = statement.query_row(params![], |row| row.get::<usize, i64>(0))?;

	Ok(u64::try_from(cp)?)
}

pub fn store_mailbox_checkpoint(conn: &Connection, checkpoint: u64) -> anyhow::Result<()> {
	conn.execute(
		r#"
			UPDATE bark_mailbox_checkpoint
			SET checkpoint = ?1, updated_at = ?2
			WHERE id = 1 AND ?1 > checkpoint
		"#,
		params![checkpoint, chrono::Utc::now()],
	)?;

	if conn.changes() == 0 {
		bail!("Checkpoint not advanced - another thread may have a higher value")
	}

	Ok(())
}

pub fn store_exit_vtxo_entry(tx: &rusqlite::Transaction, exit: &StoredExit) -> anyhow::Result<()> {
	let query = r"
		INSERT INTO bark_exit_states (vtxo_id, state, history, movement_id)
		VALUES (?1, ?2, ?3, ?4)
		ON CONFLICT (vtxo_id) DO UPDATE
		SET
			state = EXCLUDED.state,
			history = EXCLUDED.history,
			movement_id = EXCLUDED.movement_id;
	";

	// We can't use JSONB with rusqlite, so we make do with strings
	let id = exit.vtxo_id.to_string();
	let state = serde_json::to_string(&exit.state)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} state can't be serialized: {}", id, e))?;
	let history = serde_json::to_string(&exit.history)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} history can't be serialized: {}", id, e))?;
	let movement_id = exit.movement_id.map(|m| m.0);

	tx.execute(query, (id, state, history, movement_id))?;
	Ok(())
}

pub fn remove_exit_vtxo_entry(tx: &rusqlite::Transaction, id: &VtxoId) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_exit_states WHERE vtxo_id = ?1;";
	tx.execute(query, [id.to_string()])?;

	Ok(())
}

pub fn get_exit_vtxo_entries(conn: &Connection) -> anyhow::Result<Vec<StoredExit>> {
	let mut statement = conn.prepare(
		"SELECT vtxo_id, state, history, movement_id FROM bark_exit_states;",
	)?;
	let mut rows = statement.query([])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo_id = VtxoId::from_str(&row.get::<usize, String>(0)?)?;
		let state = serde_json::from_str::<ExitState>(&row.get::<usize, String>(1)?)?;
		let history = serde_json::from_str::<Vec<ExitState>>(&row.get::<usize, String>(2)?)?;
		let movement_id = row.get::<usize, Option<u32>>(3)?.map(MovementId::new);

		result.push(StoredExit { vtxo_id, state, history, movement_id });
	}

	Ok(result)
}

pub fn store_exit_child_tx(
	tx: &rusqlite::Transaction,
	exit_txid: Txid,
	child_tx: &bitcoin::Transaction,
	origin: ExitTxOrigin,
) -> anyhow::Result<()> {
	let query = r"
		INSERT INTO bark_exit_child_transactions (exit_id, child_tx, tx_origin)
		VALUES (?1, ?2, ?3)
		ON CONFLICT (exit_id) DO UPDATE
		SET
			child_tx = EXCLUDED.child_tx,
			tx_origin = EXCLUDED.tx_origin;
	";

	let exit_id = exit_txid.to_string();
	let child_transaction = consensus::serialize(child_tx);
	let origin = serde_json::to_string(&origin)
		.map_err(|e| anyhow!("ExitTxOrigin {} state can't be serialized: {}", origin, e))?;

	tx.execute(query, (exit_id, child_transaction, origin))?;
	Ok(())
}

pub fn get_exit_child_tx(
	conn: &Connection,
	exit_txid: Txid,
) -> anyhow::Result<Option<(bitcoin::Transaction, ExitTxOrigin)>> {
	let query = r"
			SELECT child_tx, tx_origin FROM bark_exit_child_transactions where exit_id = ?1;
		";
	let mut statement = conn.prepare(query)?;
	let result = statement.query_row([exit_txid.to_string()], |row| {
		let tx_bytes : Vec<u8> = row.get(0)?;
		let tx = consensus::deserialize(&tx_bytes)
			.map_err(|e| rusqlite::Error::FromSqlConversionFailure(
				tx_bytes.len(), rusqlite::types::Type::Blob, Box::new(e)
			))?;
		let origin = serde_json::from_str::<ExitTxOrigin>(&row.get::<usize, String>(1)?)
			.map_err(|e| rusqlite::Error::FromSqlConversionFailure(
				tx_bytes.len(), rusqlite::types::Type::Blob, Box::new(e)
			))?;
		Ok((tx, origin))
	});
	match result {
		Ok(result) => Ok(Some(result)),
		Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
		Err(e) => Err(format_err!("Unable to deserialize child tx for exit {}: {}", exit_txid, e)),
	}
}

pub fn upsert_wallet_action_checkpoint(
	conn: &Connection,
	id: &WalletActionId,
	checkpoint: &WalletActionCheckpoint,
) -> anyhow::Result<()> {
	let payload = serde_json::to_vec(checkpoint)
		.context("failed to serialize wallet action checkpoint")?;
	let query = "
		INSERT INTO bark_wallet_action_checkpoint (id, payload)
		VALUES (:id, :payload)
		ON CONFLICT(id) DO UPDATE SET
			payload = excluded.payload,
			updated_at = strftime('%Y-%m-%d %H:%M:%f', 'now')";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":id": id,
		":payload": payload,
	})?;
	Ok(())
}

pub fn get_wallet_action_checkpoint(
	conn: &Connection,
	id: &WalletActionId,
) -> anyhow::Result<Option<WalletActionCheckpoint>> {
	let query = "SELECT payload FROM bark_wallet_action_checkpoint WHERE id = :id";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! { ":id": id })?;

	let row = match rows.next()? {
		Some(row) => row,
		None => return Ok(None),
	};
	let payload: Vec<u8> = row.get("payload")?;
	let checkpoint = serde_json::from_slice(&payload)
		.context("failed to deserialize wallet action checkpoint")?;
	Ok(Some(checkpoint))
}

pub fn get_all_wallet_action_checkpoints(
	conn: &Connection,
) -> anyhow::Result<Vec<WalletActionCheckpoint>> {
	let query = "SELECT payload FROM bark_wallet_action_checkpoint ORDER BY created_at ASC";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let payload: Vec<u8> = row.get("payload")?;
		let checkpoint = serde_json::from_slice(&payload)
			.context("failed to deserialize wallet action checkpoint")?;
		result.push(checkpoint);
	}
	Ok(result)
}

pub fn remove_wallet_action_checkpoint(
	conn: &Connection,
	id: &WalletActionId,
) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_wallet_action_checkpoint WHERE id = :id";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! { ":id": id })?;
	Ok(())
}


pub fn record_paid_invoice(
	conn: &Connection,
	payment_hash: PaymentHash,
	preimage: Preimage,
) -> anyhow::Result<()> {
	let query = "
		INSERT INTO bark_paid_invoice (payment_hash, preimage)
		VALUES (:payment_hash, :preimage)
		ON CONFLICT(payment_hash) DO NOTHING";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
		":preimage": preimage.as_hex().to_string(),
	})?;
	Ok(())
}

pub fn get_paid_invoice(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<Option<PaidInvoice>> {
	let query = "SELECT preimage, paid_at FROM bark_paid_invoice WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! { ":payment_hash": payment_hash.as_hex().to_string() })?;

	let row = match rows.next()? {
		Some(row) => row,
		None => return Ok(None),
	};
	let preimage_str: String = row.get("preimage")?;
	let preimage = Preimage::from_str(&preimage_str)
		.context("invalid preimage hex in bark_paid_invoice")?;
	let paid_at: chrono::DateTime<chrono::Local> = row.get("paid_at")?;
	Ok(Some(PaidInvoice { payment_hash, preimage, paid_at }))
}


pub fn record_settled_lightning_receive(
	conn: &Connection,
	payment_hash: PaymentHash,
	preimage: Preimage,
	invoice: &Bolt11Invoice,
	amount: Amount,
) -> anyhow::Result<()> {
	let query = "
		INSERT INTO bark_settled_lightning_receive (payment_hash, preimage, invoice, amount_sat)
		VALUES (:payment_hash, :preimage, :invoice, :amount_sat)
		ON CONFLICT(payment_hash) DO NOTHING";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
		":preimage": preimage.as_hex().to_string(),
		":invoice": invoice.to_string(),
		":amount_sat": amount.to_sat() as i64,
	})?;
	Ok(())
}

pub fn get_settled_lightning_receive(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<Option<SettledLightningReceive>> {
	let query = "SELECT preimage, invoice, amount_sat, settled_at
		FROM bark_settled_lightning_receive WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! { ":payment_hash": payment_hash.as_hex().to_string() })?;

	let row = match rows.next()? {
		Some(row) => row,
		None => return Ok(None),
	};
	let preimage_str: String = row.get("preimage")?;
	let preimage = Preimage::from_str(&preimage_str)
		.context("invalid preimage hex in bark_settled_lightning_receive")?;
	let invoice_str: String = row.get("invoice")?;
	let invoice = Bolt11Invoice::from_str(&invoice_str)
		.context("invalid invoice in bark_settled_lightning_receive")?;
	let amount = Amount::from_sat(row.get::<_, i64>("amount_sat")? as u64);
	let settled_at: chrono::DateTime<chrono::Local> = row.get("settled_at")?;
	Ok(Some(SettledLightningReceive { payment_hash, preimage, invoice, amount, settled_at }))
}


#[cfg(test)]
mod test {
	use ark::test_util::VTXO_VECTORS;

	use crate::persist::sqlite::helpers::in_memory_db;
	use crate::persist::sqlite::migrations::MigrationContext;

	use super::*;

	#[test]
	fn test_update_vtxo_state() {
		let (_, mut conn) = in_memory_db();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		let tx = conn.transaction().unwrap();
		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let locked = VtxoState::Locked { holder: None };
		store_vtxo_with_initial_state(&tx, &vtxo_1, &locked).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_2, &locked).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_3, &locked).unwrap();

		// This update will fail because the current state is Locked
		// We only allow the state to switch from VtxoState::Spendable
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable])
			.expect_err("The vtxo isn't spendable and query should fail");

		// Perform a state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spendable, &[VtxoStateKind::Locked]).unwrap();

		// Perform a second state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable]).unwrap();

		// Ensure the state of vtxo_2 and vtxo_3 isn't modified
		let state_2 = get_vtxo_state(&tx, vtxo_2.id()).unwrap().unwrap();
		assert_eq!(state_2, locked);
		let state_2 = get_vtxo_state(&tx, vtxo_3.id()).unwrap().unwrap();
		assert_eq!(state_2, locked);
	}

	#[test]
	fn test_store_vtxo_idempotent() {
		let (_, mut conn) = in_memory_db();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		let tx = conn.transaction().unwrap();
		let vtxo = &VTXO_VECTORS.board_vtxo;

		// First insert should succeed
		let spendable = VtxoState::Spendable;
		store_vtxo_with_initial_state(&tx, vtxo, &spendable).unwrap();

		// Verify state is Spendable
		let state = get_vtxo_state(&tx, vtxo.id()).unwrap().unwrap();
		assert_eq!(state, spendable);

		// Second insert with same VTXO should succeed (idempotent)
		store_vtxo_with_initial_state(&tx, vtxo, &spendable).unwrap();

		// Second insert with different state should also succeed but NOT change state
		let locked = VtxoState::Locked { holder: None };
		store_vtxo_with_initial_state(&tx, vtxo, &locked).unwrap();

		// State should still be Spendable (original state preserved)
		let state = get_vtxo_state(&tx, vtxo.id()).unwrap().unwrap();
		assert_eq!(state, spendable);
	}

	/// Tests that update_vtxo_state_checked is idempotent when the VTXO is
	/// already in the target state. This covers the persist_round_failure
	/// retry scenario: a VTXO is unlocked (Locked -> Spendable), then on
	/// retry the same unlock is attempted again and must succeed without
	/// inserting a redundant state history row.
	#[test]
	fn test_update_vtxo_state_idempotent() {
		let (_, mut conn) = in_memory_db();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		let tx = conn.transaction().unwrap();
		let vtxo = &VTXO_VECTORS.board_vtxo;

		// Store a VTXO in Locked state.
		let locked = VtxoState::Locked { holder: None };
		store_vtxo_with_initial_state(&tx, vtxo, &locked).unwrap();

		// First unlock: Locked -> Spendable. Must succeed.
		let wv = update_vtxo_state_checked(
			&tx, vtxo.id(), VtxoState::Spendable, &[VtxoStateKind::Locked, VtxoStateKind::Spendable],
		).unwrap();
		assert_eq!(wv.state, VtxoState::Spendable);

		// Count state history rows after the first transition.
		let rows_after_first: i64 = tx.query_row(
			"SELECT COUNT(*) FROM bark_vtxo_state WHERE vtxo_id = ?1",
			[vtxo.id().to_string()], |r| r.get(0),
		).unwrap();
		// Initial Locked + transition to Spendable = 2 rows.
		assert_eq!(rows_after_first, 2);

		// Second unlock (retry): already Spendable -> Spendable. Must succeed.
		let wv = update_vtxo_state_checked(
			&tx, vtxo.id(), VtxoState::Spendable, &[VtxoStateKind::Locked, VtxoStateKind::Spendable],
		).unwrap();
		assert_eq!(wv.state, VtxoState::Spendable);

		// No redundant row inserted.
		let rows_after_second: i64 = tx.query_row(
			"SELECT COUNT(*) FROM bark_vtxo_state WHERE vtxo_id = ?1",
			[vtxo.id().to_string()], |r| r.get(0),
		).unwrap();
		assert_eq!(rows_after_second, 2);

		// Also verify that a disallowed transition still fails.
		// VTXO is Spendable, but only Spent is allowed -> must error.
		update_vtxo_state_checked(
			&tx, vtxo.id(), VtxoState::Locked { holder: None }, &[VtxoStateKind::Spent],
		).expect_err("transition from Spendable should fail when only Spent is allowed");
	}

	#[test]
	fn test_mailbox_checkpoint_stores_correct_value() {
		let (_, mut conn) = in_memory_db();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		// Initial checkpoint should be 0
		let initial = get_mailbox_checkpoint(&conn).unwrap();
		assert_eq!(initial, 0);

		// Store checkpoint 100
		store_mailbox_checkpoint(&conn, 100).unwrap();

		// Retrieved checkpoint must be exactly 100, not 0 or 1
		// This catches the bug where `SET col = ?1 AND ...` was used instead of comma
		let stored = get_mailbox_checkpoint(&conn).unwrap();
		assert_eq!(stored, 100, "Checkpoint should be exactly 100, not corrupted by SQL AND operator");

		// Storing a lower checkpoint should fail (no rows updated)
		let result = store_mailbox_checkpoint(&conn, 50);
		assert!(result.is_err(), "Storing a lower checkpoint should fail");

		// Checkpoint should still be 100
		let unchanged = get_mailbox_checkpoint(&conn).unwrap();
		assert_eq!(unchanged, 100);

		// Storing a higher checkpoint should succeed
		store_mailbox_checkpoint(&conn, 200).unwrap();
		let updated = get_mailbox_checkpoint(&conn).unwrap();
		assert_eq!(updated, 200);
	}
}
