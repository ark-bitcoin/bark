use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use bitcoin::{Amount, Network, SignedAmount, Txid};
use bitcoin::consensus;
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::hex::DisplayHex;
use bitcoin::secp256k1::PublicKey;
use chrono::DateTime;
use lightning_invoice::Bolt11Invoice;
use rusqlite::{self, named_params, params, Connection, Row, ToSql, Transaction};

use ark::ProtocolEncoding;
use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::vtxo::VtxoRef;
use bitcoin_ext::BlockDelta;

use crate::{Vtxo, VtxoId, VtxoState, WalletProperties};
use crate::exit::models::{ExitState, ExitTxOrigin};
use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem};
use crate::persist::{RoundStateId, StoredRoundState};
use crate::persist::models::{
	LightningReceive, PendingLightningSend, SerdeRoundState, SerdeUnconfirmedRound, StoredExit,
};
use crate::persist::sqlite::convert::{row_to_movement, row_to_wallet_vtxo, rows_to_wallet_vtxos};
use crate::round::{RoundState, UnconfirmedRound};
use crate::vtxo::state::{VtxoStateKind, WalletVtxo};

/// Set read-only properties for the wallet
///
/// This is fail if properties aren't already set for the wallet
pub (crate) fn set_properties(
	conn: &Connection,
	properties: &WalletProperties,
) -> anyhow::Result<()> {
	// Store the ftxo
	let query =
		"INSERT INTO bark_properties (id, network, fingerprint)
		VALUES (1, :network, :fingerprint)";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":network": properties.network.to_string(),
		":fingerprint": properties.fingerprint.to_string(),
	})?;

	Ok(())
}

pub (crate) fn fetch_properties(conn: &Connection) -> anyhow::Result<Option<WalletProperties>> {
	let query = "SELECT * FROM bark_properties";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let network: String = row.get("network")?;
		let fingerprint: String = row.get("fingerprint")?;

		Ok(Some(
			WalletProperties {
				network: Network::from_str(&network).context("invalid network")?,
				fingerprint: Fingerprint::from_str(&fingerprint).context("invalid fingerprint")?,
			}
		))
	} else {
		Ok(None)
	}
}

pub fn check_recipient_exists(conn: &Connection, recipient: &str) -> anyhow::Result<bool> {
	let exists: bool = conn.query_row(
		"SELECT EXISTS(
			SELECT 1
			FROM bark_movements m
			INNER JOIN bark_movements_sent_to st ON m.id = st.movement_id
			WHERE m.status = ?1 AND st.destination = ?2
		)",
		params!(MovementStatus::Finished.as_str(), recipient),
		|row| row.get(0)
	)?;

	Ok(exists)
}

pub fn create_new_movement(
	tx: &Transaction,
	status: MovementStatus,
	subsystem: &MovementSubsystem,
	time: DateTime<chrono::Local>,
) -> anyhow::Result<MovementId> {
	let mut statement = tx.prepare("
		INSERT INTO bark_movements (status, subsystem_name, movement_kind, intended_balance,
			effective_balance, offchain_fee, created_at, updated_at)
		VALUES (:status, :name, :kind, :intended_balance, :effective_balance, :offchain_fee,
			:created_at, :updated_at)
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
	}, |row| row.get::<_, u32>(0))?;

	Ok(MovementId::new(id))
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
					"INSERT INTO {} (movement_id, destination, amount) VALUES (?1, ?2, ?3)",
					table,
				),
				params![id, dest.destination.to_string(), dest.amount.to_sat()],
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

pub fn get_movement(conn: &Connection, id: MovementId) -> anyhow::Result<Movement> {
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

pub fn get_all_pending_boards_ids(conn: &Connection) -> anyhow::Result<Vec<VtxoId>> {
	let q = "SELECT vtxo_id FROM bark_pending_board;";
	let mut statement = conn.prepare(q)?;
	let mut rows = statement.query([])?;
	let mut pending_boards = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo_id = row.get::<_, String>(0)?;
		pending_boards.push(VtxoId::from_str(&vtxo_id)?);
	}

	Ok(pending_boards)
}

pub fn get_pending_board_movement_id(
	conn: &Connection,
	vtxo_id: VtxoId,
) -> anyhow::Result<MovementId> {
	Ok(conn.prepare(
		"SELECT movement_id FROM bark_pending_board WHERE vtxo_id = ?1",
	)?.query_row(
		params![vtxo_id.to_string()],
		|row| Ok(MovementId::new(row.get(0)?)),
	)?)
}

pub fn store_new_pending_board(
	tx: &Transaction,
	vtxo_id: VtxoId,
	funding_tx: &bitcoin::Transaction,
	movement_id: MovementId,
) -> anyhow::Result<()> {
	let mut statement = tx.prepare("
		INSERT INTO bark_pending_board (vtxo_id, funding_tx, movement_id)
		VALUES (:vtxo_id, :funding_tx, :movement_id);"
	)?;

	statement.execute(named_params! {
		":vtxo_id": vtxo_id.to_string(),
		":funding_tx": bitcoin::consensus::encode::serialize_hex(&funding_tx),
		":movement_id": movement_id.0,
	})?;
	Ok(())
}

pub fn remove_pending_board(
	tx: &Transaction,
	vtxo_id: &VtxoId,
) -> anyhow::Result<()> {
	let q = "DELETE FROM bark_pending_board WHERE vtxo_id = :vtxo_id;";
	let mut statement = tx.prepare(q)?;
	statement.execute(named_params! {
		":vtxo_id": vtxo_id.to_string(),
	})?;
	Ok(())
}

pub fn store_vtxo_with_initial_state(
	tx: &Transaction,
	vtxo: &Vtxo,
	state: &VtxoState,
) -> anyhow::Result<()> {
	// Store the vtxo
	let q1 =
		"INSERT INTO bark_vtxo (id, expiry_height, amount_sat, raw_vtxo)
		VALUES (:vtxo_id, :expiry_height, :amount_sat, :raw_vtxo);";
	let mut statement = tx.prepare(q1)?;
	statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.expiry_height(),
		":amount_sat": vtxo.amount().to_sat(),
		":raw_vtxo": vtxo.serialize(),
	})?;

	// Store the initial state
	let q2 =
		"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
		VALUES (:vtxo_id, :state_kind, :state);";
	let mut statement = tx.prepare(q2)?;
	statement.execute(named_params! {
		":vtxo_id": vtxo.id().to_string(),
		":state_kind": state.kind().as_str(),
		":state": serde_json::to_vec(&state)?,
	})?;

	Ok(())
}

pub fn store_round_state(
	tx: &rusqlite::Transaction,
	state: &RoundState,
) -> anyhow::Result<RoundStateId> {
	let bytes = rmp_serde::to_vec(&SerdeRoundState::from(state)).expect("can serialize");
	let mut stmt = tx.prepare(
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
	let bytes = rmp_serde::to_vec(&SerdeRoundState::from(&state.state)).expect("can serialize");
	let mut stmt = conn.prepare(
		"UPDATE bark_round_state SET state = :state WHERE id = :id",
	)?;
	stmt.execute(named_params! {
		":id": state.id.0 as i64,
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

pub fn load_round_states(
	conn: &Connection,
) -> anyhow::Result<Vec<StoredRoundState>> {
	let mut stmt = conn.prepare("SELECT id, state FROM bark_round_state")?;
	let mut rows = stmt.query([])?;

	let mut ret = Vec::new();
	while let Some(row) = rows.next()? {
		let state = rmp_serde::from_slice::<SerdeRoundState>(&row.get::<_, Vec<u8>>(1)?)?;
		ret.push(StoredRoundState {
			id: RoundStateId(row.get::<_, i64>(0)? as u32),
			state: state.into(),
		});
	}
	Ok(ret)
}

pub fn store_recovered_past_round(
	conn: &Connection,
	round: &UnconfirmedRound,
) -> anyhow::Result<()> {
	let bytes = rmp_serde::to_vec(&SerdeUnconfirmedRound::from(round)).expect("can serialize");
	let mut stmt = conn.prepare(
		"INSERT INTO bark_recovered_past_round (funding_txid, past_round_state) \
			VALUES (:funding_txid, :state)",
	)?;
	stmt.execute(named_params! {
		":funding_txid": round.funding_txid().to_string(),
		":state": bytes,
	})?;
	Ok(())
}

pub fn remove_recovered_past_round(
	conn: &Connection,
	funding_txid: Txid,
) -> anyhow::Result<()> {
	let mut stmt = conn.prepare(
		"DELETE FROM bark_recovered_past_round WHERE funding_txid = :funding_txid",
	)?;
	stmt.execute(named_params! {
		":funding_txid": funding_txid.to_string(),
	})?;
	Ok(())
}

pub fn load_recovered_past_rounds(
	conn: &Connection,
) -> anyhow::Result<Vec<UnconfirmedRound>> {
	let mut stmt = conn.prepare("SELECT past_round_state FROM bark_recovered_past_round")?;
	let mut rows = stmt.query([])?;

	let mut ret = Vec::new();
	while let Some(row) = rows.next()? {
		let state = rmp_serde::from_slice::<SerdeUnconfirmedRound>(&row.get::<_, Vec<u8>>(0)?)?;
		ret.push(state.into());
	}
	Ok(ret)
}

pub fn get_all_pending_lightning_send(conn: &Connection) -> anyhow::Result<Vec<PendingLightningSend>> {
	let mut statement = conn.prepare("
		SELECT htlc_vtxo_ids, invoice, amount_sats, movement_id FROM bark_pending_lightning_send
	")?;
	let mut rows = statement.query(())?;

	let mut pending_lightning_sends = Vec::new();
	while let Some(row) = rows.next()? {
		let invoice = row.get::<_, String>("invoice")?;
		let htlc_vtxo_ids = serde_json::from_str::<Vec<VtxoId>>(&row.get::<_, String>(0)?)?;
		let amount_sats = row.get::<_, i64>("amount_sats")?;
		let movement_id = MovementId::new(row.get::<_, u32>("movement_id")?);

		let mut htlc_vtxos = Vec::new();
		for htlc_vtxo_id in htlc_vtxo_ids {
			htlc_vtxos.push(get_wallet_vtxo_by_id(conn, htlc_vtxo_id)?.context("no vtxo found")?);
		}

		pending_lightning_sends.push(PendingLightningSend {
			invoice: Invoice::from_str(&invoice)?,
			amount: Amount::from_sat(amount_sats as u64),
			htlc_vtxos,
			movement_id,
		});
	}

	Ok(pending_lightning_sends)
}

pub fn store_new_pending_lightning_send<V: VtxoRef>(
	conn: &Connection,
	invoice: &Invoice,
	amount: &Amount,
	htlc_vtxo_ids: &[V],
	movement_id: MovementId,
) -> anyhow::Result<PendingLightningSend> {
	let query = "
		INSERT INTO bark_pending_lightning_send (invoice, payment_hash, amount_sats, htlc_vtxo_ids, movement_id)
		VALUES (:invoice, :payment_hash, :amount_sats, :htlc_vtxo_ids, :movement_id)
	";

	let mut statement = conn.prepare(query)?;

	let mut htlc_vtxos = Vec::new();
	let mut vtxo_ids = Vec::new();
	for v in htlc_vtxo_ids {
		htlc_vtxos.push(get_wallet_vtxo_by_id(conn, v.vtxo_id())?.context("no vtxo found")?);
		vtxo_ids.push(v.vtxo_id().to_string());
	}

	statement.execute(named_params! {
		":invoice": invoice.to_string(),
		":payment_hash": invoice.payment_hash().as_hex().to_string(),
		":amount_sats": amount.to_sat(),
		":htlc_vtxo_ids": serde_json::to_string(&vtxo_ids)?,
		":movement_id": movement_id.0,
	})?;

	Ok(PendingLightningSend {
		invoice: invoice.clone(),
		amount: *amount,
		htlc_vtxos,
		movement_id,
	})
}

pub fn remove_pending_lightning_send(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_pending_lightning_send WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! { ":payment_hash": payment_hash.as_hex().to_string() })?;

	Ok(())
}

pub fn get_wallet_vtxo_by_id(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<WalletVtxo>> {
	let query = "SELECT raw_vtxo, state FROM vtxo_view WHERE id = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		Ok(Some(row_to_wallet_vtxo(&row)?))
	} else {
		Ok(None)
	}
}

pub fn get_all_vtxos(conn: &Connection) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = "
		SELECT raw_vtxo, state
		FROM vtxo_view
		ORDER BY expiry_height ASC, amount_sat DESC";

	let mut statement = conn.prepare(query)?;
	let rows = statement.query(())?;

	rows_to_wallet_vtxos(rows)
}

pub fn get_vtxos_by_state(
	conn: &Connection,
	state: &[VtxoStateKind]
) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = "
		SELECT raw_vtxo, state
		FROM vtxo_view
		WHERE state_kind IN (SELECT atom FROM json_each(?))
		ORDER BY expiry_height ASC, amount_sat DESC";

	let mut statement = conn.prepare(query)?;
	let rows = statement.query(&[&serde_json::to_string(&state)?])?;

	rows_to_wallet_vtxos(rows)
}

pub fn delete_vtxo(
	tx: &rusqlite::Transaction,
	id: VtxoId
) -> anyhow::Result<Option<Vtxo>> {
	// Delete all vtxo-states
	let query = "DELETE FROM bark_vtxo_state WHERE vtxo_id = ?1";
	tx.execute(query, [id.to_string()])?;

	let query = "DELETE FROM bark_vtxo WHERE id = ?1 RETURNING raw_vtxo";
	let mut statement = tx.prepare(query)?;

	let vtxo = statement
		.query_and_then(
			[id.to_string()],
			|row| -> anyhow::Result<Vtxo> {
				let raw_vtxo : Vec<u8> = row.get(0)?;
				Ok(Vtxo::deserialize(&raw_vtxo)?)
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
			state_kind IN (SELECT atom FROM json_each(:old_states))";

	let mut statement = conn.prepare(query)?;
	let nb_inserted = statement.execute(named_params! {
		":vtxo_id": vtxo_id.to_string(),
		":state_kind": new_state.kind().as_str(),
		":state": serde_json::to_vec(&new_state)?,
		":old_states": &serde_json::to_string(old_states)?,
	})?;

	match nb_inserted {
		0 => bail!("No vtxo with provided id or old states"),
		1 => Ok(get_wallet_vtxo_by_id(conn, vtxo_id)?.unwrap()),
		_ => panic!("Corrupted database. A vtxo can have only one state"),
	}
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

pub fn store_lightning_receive(
	conn: &Connection,
	payment_hash: PaymentHash,
	preimage: Preimage,
	invoice: &Bolt11Invoice,
	htlc_recv_cltv_delta: BlockDelta,
) -> anyhow::Result<()> {
	let query = "
		INSERT INTO bark_pending_lightning_receive (payment_hash, preimage, invoice,
			htlc_recv_cltv_delta)
		VALUES (:payment_hash, :preimage, :invoice, :htlc_recv_cltv_delta);
	";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
		":preimage": preimage.as_hex().to_string(),
		":invoice": invoice.to_string(),
		":htlc_recv_cltv_delta": htlc_recv_cltv_delta,
	})?;

	Ok(())
}

fn get_htlc_vtxos(conn: &Connection, row: &Row<'_>) -> anyhow::Result<Option<Vec<WalletVtxo>>> {
	match row.get::<_, Option<String>>("htlc_vtxo_ids")? {
		Some(vtxo_ids_str) => {
			let vtxo_ids = serde_json::from_str::<Vec<VtxoId>>(&vtxo_ids_str)?;
			let mut vtxos = Vec::new();
			for vtxo_id in vtxo_ids {
				vtxos.push(get_wallet_vtxo_by_id(conn, vtxo_id)?.context("no vtxo found")?);
			}
			Ok(Some(vtxos))
		},
		None => Ok(None),
	}
}

pub fn get_all_pending_lightning_receives<'a>(
	conn: &'a Connection,
) -> anyhow::Result<Vec<LightningReceive>> {
	let query = "
		SELECT payment_hash, preimage, invoice, htlc_vtxo_ids,
			preimage_revealed_at, htlc_recv_cltv_delta, movement_id
		FROM bark_pending_lightning_receive
		ORDER BY created_at DESC";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(LightningReceive {
			payment_hash: PaymentHash::from_str(&row.get::<_, String>("payment_hash")?)?,
			payment_preimage: Preimage::from_str(&row.get::<_, String>("preimage")?)?,
			preimage_revealed_at: row.get::<_, Option<u64>>("preimage_revealed_at")?,
			invoice: Bolt11Invoice::from_str(&row.get::<_, String>("invoice")?)?,
			htlc_recv_cltv_delta: row.get::<_, BlockDelta>("htlc_recv_cltv_delta")?,
			htlc_vtxos: get_htlc_vtxos(conn, &row)?,
			movement_id: row.get::<_, Option<u32>>("movement_id")?.map(MovementId::new),
		});
	}

	Ok(result)
}

pub fn set_preimage_revealed(conn: &Connection, payment_hash: PaymentHash) -> anyhow::Result<()> {
	let query = "UPDATE bark_pending_lightning_receive SET preimage_revealed_at = :revealed_at \
		WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
		":revealed_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
	})?;
	Ok(())
}

pub fn update_lightning_receive(
	conn: &Connection,
	payment_hash: PaymentHash,
	htlc_vtxo_ids: &[VtxoId],
	movement_id: MovementId,
) -> anyhow::Result<()> {
	let query = "
		UPDATE bark_pending_lightning_receive
		SET htlc_vtxo_ids = :htlc_vtxo_ids, movement_id = :movement_id
		WHERE payment_hash = :payment_hash";

	let mut statement = conn.prepare(query)?;

	let mut vtxo_ids = Vec::new();
	for v in htlc_vtxo_ids {
		get_wallet_vtxo_by_id(conn, *v)?.context("no vtxo found")?;
		vtxo_ids.push(v.vtxo_id().to_string());
	}

	statement.execute(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
		":htlc_vtxo_ids": serde_json::to_string(&vtxo_ids)?,
		":movement_id": Some(movement_id.0),
	})?;

	Ok(())
}

pub fn remove_pending_lightning_receive(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_pending_lightning_receive WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! { ":payment_hash": payment_hash.as_hex().to_string() })?;

	Ok(())
}

pub fn fetch_lightning_receive_by_payment_hash(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<Option<LightningReceive>> {
	let query = "SELECT * FROM bark_pending_lightning_receive WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! {
		":payment_hash": payment_hash.as_hex().to_string(),
	})?;

	let row = match rows.next()? {
		Some(row) => row,
		None => return Ok(None),
	};

	Ok(Some(LightningReceive {
		payment_hash: PaymentHash::from_str(&row.get::<_, String>("payment_hash")?)?,
		payment_preimage: Preimage::from_str(&row.get::<_, String>("preimage")?)?,
		preimage_revealed_at: row.get::<_, Option<u64>>("preimage_revealed_at")?,
		invoice: Bolt11Invoice::from_str(&row.get::<_, String>("invoice")?)?,
		htlc_recv_cltv_delta: row.get::<_, BlockDelta>("htlc_recv_cltv_delta")?,
		htlc_vtxos: get_htlc_vtxos(conn, &row)?,
		movement_id: row.get::<_, Option<u32>>("movement_id")?.map(MovementId::new),
	}))
}

pub fn store_exit_vtxo_entry(tx: &rusqlite::Transaction, exit: &StoredExit) -> anyhow::Result<()> {
	let query = r"
		INSERT INTO bark_exit_states (vtxo_id, state, history)
		VALUES (?1, ?2, ?3)
		ON CONFLICT (vtxo_id) DO UPDATE
		SET
			state = EXCLUDED.state,
			history = EXCLUDED.history;
	";

	// We can't use JSONB with rusqlite, so we make do with strings
	let id = exit.vtxo_id.to_string();
	let state = serde_json::to_string(&exit.state)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} state can't be serialized: {}", id, e))?;
	let history = serde_json::to_string(&exit.history)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} history can't be serialized: {}", id, e))?;

	tx.execute(query, (id, state, history))?;
	Ok(())
}

pub fn remove_exit_vtxo_entry(tx: &rusqlite::Transaction, id: &VtxoId) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_exit_states WHERE vtxo_id = ?1;";
	tx.execute(query, [id.to_string()])?;

	Ok(())
}

pub fn get_exit_vtxo_entries(conn: &Connection) -> anyhow::Result<Vec<StoredExit>> {
	let mut statement = conn.prepare("SELECT vtxo_id, state, history FROM bark_exit_states;")?;
	let mut rows = statement.query([])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo_id = VtxoId::from_str(&row.get::<usize, String>(0)?)?;
		let state = serde_json::from_str::<ExitState>(&row.get::<usize, String>(1)?)?;
		let history = serde_json::from_str::<Vec<ExitState>>(&row.get::<usize, String>(2)?)?;

		result.push(StoredExit { vtxo_id, state, history });
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



#[cfg(test)]
mod test {
	use ark::vtxo::test::VTXO_VECTORS;

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

		let locked = VtxoState::Locked { movement_id: None };
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
}
