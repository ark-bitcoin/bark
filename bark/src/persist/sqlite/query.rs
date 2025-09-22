use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use ark::musig::{DangerousSecretNonce, SecretNonce};
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, Network, Txid};
use bitcoin::consensus;
use bitcoin::bip32::Fingerprint;
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;
use rusqlite::{self, named_params, Connection, ToSql, Transaction};

use ark::ProtocolEncoding;
use ark::lightning::{PaymentHash, Preimage};
use ark::rounds::{RoundId, RoundSeq};
use json::exit::ExitState;
use json::exit::states::ExitTxOrigin;

use crate::persist::sqlite::convert::{row_to_secret_nonces, row_to_round_state};
use crate::{Pagination, RoundParticipation, Vtxo, VtxoId, VtxoState, WalletProperties};
use crate::vtxo_state::{VtxoStateKind, WalletVtxo};
use crate::movement::{Movement, MovementKind};
use crate::persist::models::{LightningReceive, StoredExit, StoredVtxoRequest};
use crate::round::{AttemptStartedState, PendingConfirmationState, RoundState, RoundStateKind};

use super::convert::{row_to_lightning_receive, row_to_movement};

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

pub fn create_movement(conn: &Connection, kind: MovementKind, fees_sat: Option<Amount>) -> anyhow::Result<i32> {
	// Store the vtxo
	let query = "INSERT INTO bark_movement (kind, fees_sat) VALUES (:kind, :fees_sat) RETURNING *;";
	let mut statement = conn.prepare(query)?;
	let movement_id = statement.query_row(named_params! {
		":kind" : kind.as_str(),
		":fees_sat" : fees_sat.unwrap_or(Amount::ZERO).to_sat()
	}, |row| row.get::<_, i32>(0))?;

	Ok(movement_id)
}

pub fn create_recipient(
	conn: &Connection,
	movement: i32,
	recipient: &str,
	amount: Amount,
) -> anyhow::Result<i32> {
	// Store the vtxo
	let query = "
		INSERT INTO bark_recipient (movement, recipient, amount_sat)
		VALUES (:movement, :recipient, :amount_sat) RETURNING *;";

	let mut statement = conn.prepare(query)?;
	let recipient_id = statement.query_row(named_params! {
		":movement": movement,
		":recipient" : recipient,
		":amount_sat": amount.to_sat()
	}, |row| row.get::<_, i32>(0))?;

	Ok(recipient_id)
}

pub fn check_recipient_exists(conn: &Connection, recipient: &str) -> anyhow::Result<bool> {
	let query = "SELECT COUNT(*) FROM bark_recipient WHERE recipient = :recipient";

	let mut statement = conn.prepare(query)?;
	let exists = statement.query_row(named_params! {
		":recipient" : recipient,
	}, |row| Ok(row.get::<_, i32>(0)? > 0))?;

	Ok(exists)
}

pub fn get_paginated_movements(conn: &Connection, pagination: Pagination) -> anyhow::Result<Vec<Movement>> {
	let take = pagination.page_size;
	let skip = pagination.page_index * take;

	let query = "
		SELECT * FROM movement_view
		ORDER BY movement_view.created_at DESC
		LIMIT :take
		OFFSET :skip
	";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! {
		":take" : take,
		":skip" : skip,
	})?;

	let mut movements = Vec::with_capacity(take as usize);
	while let Some(row) = rows.next()? {
		movements.push(row_to_movement(row)?);
	}

	Ok(movements)
}

pub fn store_vtxo_with_initial_state(
	tx: &rusqlite::Transaction,
	vtxo: &Vtxo,
	movement_id: i32,
	state: &VtxoState,
) -> anyhow::Result<()> {
	// Store the ftxo
	let q1 =
		"INSERT INTO bark_vtxo (id, expiry_height, amount_sat, received_in, raw_vtxo)
		VALUES (:vtxo_id, :expiry_height, :amount_sat, :received_in, :raw_vtxo);";
	let mut statement = tx.prepare(q1)?;
	statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.expiry_height(),
		":amount_sat": vtxo.amount().to_sat(),
		":received_in": movement_id,
		":raw_vtxo": vtxo.serialize(),
	})?;

	// Store the initial state
	let q2 =
		"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
		VALUES (:vtxo_id, :state_kind, :state);";
	let mut statement = tx.prepare(q2)?;
	statement.execute(named_params! {
		":vtxo_id": vtxo.id().to_string(),
		":state_kind": state.as_kind().as_str(),
		":state": serde_json::to_vec(&state)?,
	})?;

	Ok(())
}

/// Returns the highest attempt for a given round sequence
pub fn get_round_attempt_by_id(conn: &Connection, round_attempt_id: i64) -> anyhow::Result<Option<RoundState>> {
	let query = "
		SELECT id, round_seq, attempt_seq, status, inputs, payment_requests,
			offboard_requests, round_txid, round_tx, vtxos, cosign_keys,
			vtxo_forfeited_in_round, vtxo_tree
		FROM round_view
		WHERE id = :round_attempt_id";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([round_attempt_id])?;

	if let Some(row) = rows.next()? {
		Ok(Some(row_to_round_state(row)?))
	} else {
		Ok(None)
	}
}

/// Return the last round attempt for a given round id
pub fn get_round_attempt_by_round_txid(
	conn: &Connection,
	round_id: RoundId,
) -> anyhow::Result<Option<RoundState>> {
	let query = "
		SELECT id, round_seq, attempt_seq, status, inputs, payment_requests,
			offboard_requests, round_txid, round_tx, vtxos, cosign_keys,
			vtxo_forfeited_in_round, vtxo_tree
		FROM round_view
		WHERE round_txid = :round_id";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([round_id.to_string()])?;

	if let Some(row) = rows.next()? {
		Ok(Some(row_to_round_state(row)?))
	} else {
		Ok(None)
	}
}

pub fn list_pending_rounds(conn: &Connection)
	-> anyhow::Result<Vec<RoundState>>
{
	let pending_rounds = [
		RoundStateKind::AttemptStarted,
		RoundStateKind::PaymentSubmitted,
		RoundStateKind::VtxoTreeSigned,
		RoundStateKind::ForfeitSigned,
		RoundStateKind::PendingConfirmation,
	];

	let query = "
		SELECT  id, round_seq, attempt_seq, status, inputs, payment_requests,
			offboard_requests, round_txid, round_tx, vtxos, cosign_keys,
			vtxo_forfeited_in_round, vtxo_tree
		FROM round_view
		WHERE status IN (SELECT atom FROM json_each(?))";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(&[&serde_json::to_string(&pending_rounds)?])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(row_to_round_state(row)?);
	}

	Ok(result)
}

pub fn store_new_round_attempt(
	tx: &Transaction,
	round_seq: RoundSeq,
	attempt_seq: usize,
	participation: RoundParticipation,
) -> anyhow::Result<AttemptStartedState> {
	// Store the round
	let mut statement = tx.prepare("
		INSERT INTO bark_round_attempt (round_seq, attempt_seq, payment_requests, offboard_requests, status)
		VALUES (:round_seq, :attempt_seq, :payment_requests, :offboard_requests, :status)
		RETURNING id;
	")?;

	let round_attempt_id = statement.query_row(named_params! {
		":status": RoundStateKind::AttemptStarted.to_string(),
		":round_seq": round_seq.inner(),
		":attempt_seq": attempt_seq,
		":payment_requests": serde_json::to_vec(&participation.outputs)?,
		":offboard_requests": serde_json::to_vec(&participation.offboards)?,
	}, |row| row.get::<_, i64>("id"))?;

	// Lock vtxos
	let mut statement = tx.prepare("
		UPDATE bark_vtxo
		SET locked_in_round_attempt_id = :locked_in_round_attempt_id
		WHERE id = :id"
	)?;
	for vtxo in &participation.inputs {
		statement.execute(named_params! {
			":locked_in_round_attempt_id": round_attempt_id,
			":id": vtxo.id().to_string(),
		})?;
	}

	Ok(AttemptStartedState { round_attempt_id, round_seq, attempt_seq, participation })
}

pub fn store_round_state_update(
	tx: &Transaction,
	round_state: RoundState,
	prev_state: RoundState,
) -> anyhow::Result<RoundState> {
	let status = round_state.kind();
	let round_attempt_id = round_state.round_attempt_id();

	match round_state {
		RoundState::AttemptStarted(_) => {
			unreachable!("Cannot update to round started state");
		},
		RoundState::PaymentSubmitted(state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt
				SET status = :status, cosign_keys = :cosign_keys
				WHERE id = :round_attempt_id
			")?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
				":cosign_keys": serde_json::to_vec(&state.cosign_keys)?,
			})?;
		},
		RoundState::VtxoTreeSigned(ref state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt
				SET round_tx = :round_tx, round_txid = :round_txid, status = :status, vtxo_tree = :vtxo_tree
				WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
				":round_txid": state.unsigned_round_tx.compute_txid().to_string(),
				":round_tx": serialize_hex(&state.unsigned_round_tx),
				":vtxo_tree": state.vtxo_tree.serialize(),
			})?;
		},
		RoundState::ForfeitSigned(ref state) => {
			for forfeit in &state.forfeited_vtxos {
				let mut statement = tx.prepare("
					INSERT INTO vtxo_forfeited_in_round (round_attempt_id, vtxo_id, double_spend_txid)
					VALUES (:round_attempt_id, :vtxo_id, :double_spend_txid)
					ON CONFLICT (round_attempt_id, vtxo_id) DO UPDATE SET
						double_spend_txid = :double_spend_txid
				")?;

				statement.execute(named_params! {
					":round_attempt_id": state.round_attempt_id,
					":vtxo_id": forfeit.vtxo_id.to_string(),
					":double_spend_txid": forfeit.double_spend_txid.map(|txid| txid.to_string()),
				})?;
			}

			let vtxos = state.vtxos.iter()
				.map(|v| v.serialize())
				.collect::<Vec<_>>();

			let mut statement = tx.prepare("
				UPDATE bark_round_attempt SET
					vtxos = :vtxos,
					status = :status
				WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
				":vtxos": serde_json::to_vec(&vtxos)?,
			})?;
		},
		RoundState::PendingConfirmation(ref state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt
				SET status = :status, round_tx = :round_tx, round_txid = :round_txid
				WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_txid": state.round_tx.compute_txid().to_string(),
				":round_tx": serialize_hex(&state.round_tx),
				":round_attempt_id": state.round_attempt_id,
			})?;
		},
		RoundState::RoundConfirmed(ref state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt
				SET status = :status
				WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
			})?;
		},
		RoundState::RoundAbandoned(ref state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt SET status = :status WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
			})?;

			unlink_vtxo_from_round(tx, &prev_state)?;
		},
		RoundState::RoundCancelled(ref state) => {
			let mut statement = tx.prepare("
				UPDATE bark_round_attempt
				SET status = :status
				WHERE id = :round_attempt_id"
			)?;

			statement.execute(named_params! {
				":status": status.to_string(),
				":round_attempt_id": state.round_attempt_id,
			})?;

			for forfeit in &state.forfeited_vtxos {
				// Mark forfeit links as double spent
				let mut statement = tx.prepare("
					UPDATE vtxo_forfeited_in_round
					SET double_spend_txid = :double_spend_txid
					WHERE round_attempt_id = :round_attempt_id"
				)?;
				statement.execute(named_params! {
					":round_attempt_id": state.round_attempt_id,
					":double_spend_txid": forfeit.double_spend_txid.map(|txid| txid.to_string()),
				})?;
			}

			unlink_vtxo_from_round(tx, &prev_state)?;
		},
	};

	Ok(get_round_attempt_by_id(tx, round_attempt_id)?.expect("we just inserted round"))
}

pub fn store_secret_nonces(tx: &Transaction, round_attempt_id: i64, secret_nonces: Vec<Vec<SecretNonce>>) -> anyhow::Result<()> {
	let serialized_nonces = secret_nonces.into_iter()
		.map(|sec_nonces| {
			let sec_nonces = sec_nonces.into_iter()
				.map(DangerousSecretNonce::new).collect::<Vec<_>>();
			sec_nonces
		})
		.collect::<Vec<_>>();

	let mut statement = tx.prepare("
		UPDATE bark_round_attempt SET secret_nonces = :secret_nonces WHERE id = :round_attempt_id
	")?;

	statement.execute(named_params! {
		":round_attempt_id": round_attempt_id,
		":secret_nonces": serde_json::to_vec(&serialized_nonces)?,
	})?;

	Ok(())
}

/// Takes the cosign nonces and keys used for a round and clear them in the database
///
/// If we are in PaymentSubmitted state but there is no cosign nonces or
/// keys, it surely means that we already didn't a musig session but
/// couldn't progress the round, so we need to abandon the current one and
/// wait for a new one.
pub fn take_secret_nonces(tx: &Transaction, round_attempt_id: i64) -> anyhow::Result<Option<Vec<Vec<SecretNonce>>>> {
	let mut statement = tx.prepare("
		SELECT secret_nonces, cosign_keys FROM bark_round_attempt WHERE id = :round_attempt_id"
	)?;

	let mut rows = statement.query(named_params! {
		":round_attempt_id": round_attempt_id,
	})?;

	let secret_nonces = rows.next()?
		.map(|row| row_to_secret_nonces(&row)).transpose()?
		.flatten();

	let mut statement = tx.prepare("
		UPDATE bark_round_attempt SET secret_nonces = NULL, cosign_keys = NULL WHERE id = :round_attempt_id"
	)?;
	statement.execute(named_params! { ":round_attempt_id": round_attempt_id })?;

	Ok(secret_nonces)
}

pub fn store_pending_confirmation_round(
	tx: &Transaction,
	round_txid: RoundId,
	round_tx: bitcoin::Transaction,
	reqs: Vec<StoredVtxoRequest>,
	vtxos: Vec<Vtxo>,
) -> anyhow::Result<PendingConfirmationState> {
	// Store the round
	let mut statement = tx.prepare("
		INSERT INTO bark_round_attempt (round_tx, round_txid, payment_requests, offboard_requests, vtxos, status)
		VALUES (:round_tx, :round_txid, :payment_requests, :offboard_requests, :vtxos, :status)
		RETURNING id;"
	)?;

	let round_attempt_id = statement.query_row(named_params! {
		":round_txid": round_txid.to_string(),
		":status": RoundStateKind::PendingConfirmation.to_string(),
		":round_tx": serialize_hex(&round_tx),
		":payment_requests": serde_json::to_vec(&reqs)?,
		":offboard_requests": serde_json::to_vec::<Vec<()>>(&vec![])?,
		":vtxos": serde_json::to_vec(&vtxos.iter().map(|v| v.serialize()).collect::<Vec<_>>())?,
	}, |row| row.get::<_, i64>("id"))?;

	Ok(get_round_attempt_by_id(tx, round_attempt_id)?.expect("we just inserted round")
		.into_pending_confirmation().unwrap())
}

fn unlink_vtxo_from_round(
	tx: &Transaction,
	round: &RoundState,
) -> anyhow::Result<()> {
	let mut statement = tx.prepare("
		UPDATE bark_vtxo
		SET locked_in_round_attempt_id = NULL
		WHERE id = :id AND locked_in_round_attempt_id = :round_attempt_id"
	)?;

	if let Some(participation) = round.participation() {
		for vtxo in &participation.inputs {
			let nb_updated = statement.execute(named_params! {
				":round_attempt_id": round.round_attempt_id(),
				":id": vtxo.id().to_string(),
			})?;

			match nb_updated {
				0 => panic!("Corrupted database. No vtxo with id {} found in round {}", vtxo.id(), round.round_attempt_id()),
				1 => {},
				_ => panic!("Corrupted database. Found multiple vtxos with the same id"),
			}
		}
	}

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
		let vtxo = Vtxo::deserialize(&row.get::<_, Vec<u8>>("raw_vtxo")?)?;
		let state = serde_json::from_slice::<VtxoState>(&row.get::<_, Vec<u8>>("state")?)?;
		Ok(Some(WalletVtxo { vtxo, state }))
	} else {
		Ok(None)
	}
}

pub fn get_vtxos_by_state(
	conn: &Connection,
	state: &[VtxoStateKind]
) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = "
		SELECT raw_vtxo, state
		FROM vtxo_view
		WHERE state_kind IN (SELECT atom FROM json_each(?)) AND locked_in_round_attempt_id IS NULL
		ORDER BY expiry_height ASC, amount_sat DESC";

	let mut statement = conn.prepare(query)?;

	let mut rows = statement.query(&[&serde_json::to_string(&state)?])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo = {
			let raw_vtxo : Vec<u8> = row.get("raw_vtxo")?;
			Vtxo::deserialize(&raw_vtxo)?
		};

		let state = {
			let raw_state : Vec<u8> = row.get("state")?;
			serde_json::from_slice::<VtxoState>(&raw_state)?
		};

		result.push(WalletVtxo { vtxo, state });
	}
	Ok(result)
}

pub fn get_in_round_vtxos(conn: &Connection) -> anyhow::Result<Vec<Vtxo>> {
	let query = "
		SELECT raw_vtxo
		FROM vtxo_view
		WHERE locked_in_round_attempt_id IS NOT NULL AND state_kind = ?1";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([VtxoStateKind::Spendable.as_str()])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let raw_vtxo= row.get::<_, Vec<u8>>("raw_vtxo")?;
		let vtxo = Vtxo::deserialize(&raw_vtxo)?;
		result.push(vtxo);
	}
	Ok(result)
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

pub fn link_spent_vtxo_to_movement(
	conn: &Connection,
	id: VtxoId,
	movement_id: i32
) -> anyhow::Result<()> {
	let query = "UPDATE bark_vtxo SET spent_in = :spent_in WHERE id = :vtxo_id";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":vtxo_id": id.to_string(),
		":spent_in": movement_id
	})?;

	Ok(())
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
		":state_kind": new_state.as_kind().as_str(),
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
) -> anyhow::Result<()> {
	let query = "
		INSERT INTO bark_lightning_receive (payment_hash, preimage, invoice)
		VALUES (:payment_hash, :preimage, :invoice);
	";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":payment_hash": payment_hash.to_vec(),
		":preimage": preimage.to_vec(),
		":invoice": invoice.to_string(),
	})?;

	Ok(())
}

pub fn get_paginated_lightning_receives<'a>(
	conn: &'a Connection,
	pagination: Pagination,
) -> anyhow::Result<Vec<LightningReceive>> {
	let query = "SELECT * FROM bark_lightning_receive \
		ORDER BY created_at DESC LIMIT :take OFFSET :skip";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! {
		":take": pagination.page_size,
		":skip": pagination.page_index * pagination.page_size,
	})?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		result.push(row_to_lightning_receive(&row)?);
	}

	Ok(result)
}

pub fn set_preimage_revealed(conn: &Connection, payment_hash: PaymentHash) -> anyhow::Result<()> {
	let query = "UPDATE bark_lightning_receive SET preimage_revealed_at = :revealed_at \
		WHERE payment_hash = :payment_hash";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":payment_hash": payment_hash.to_vec(),
		":revealed_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
	})?;
	Ok(())
}

pub fn fetch_lightning_receive_by_payment_hash(
	conn: &Connection,
	payment_hash: PaymentHash,
) -> anyhow::Result<Option<LightningReceive>> {
	let query = "SELECT * FROM bark_lightning_receive WHERE payment_hash = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((payment_hash.as_ref(), ))?;

	Ok(rows.next()?.map(|row| row_to_lightning_receive(&row)).transpose()?)
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

	use crate::movement::MovementRecipient;
	use crate::persist::sqlite::test::in_memory;
	use crate::persist::sqlite::migrations::MigrationContext;
	use crate::persist::StoredVtxoRequest;

	use super::*;

	#[test]
	fn test_update_vtxo_state() {
		let (_, mut conn) = in_memory();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		let tx = conn.transaction().unwrap();
		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let movement_id = create_movement(&tx, MovementKind::Board, None).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_1, movement_id, &VtxoState::UnregisteredBoard).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_2, movement_id, &VtxoState::UnregisteredBoard).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_3, movement_id, &VtxoState::UnregisteredBoard).unwrap();

		// This update will fail because the current state is UnregisteredBoard
		// We only allow the state to switch from VtxoState::Spendable
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable])
			.expect_err("The vtxo isn't spendable and query should fail");

		// Perform a state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spendable, &[VtxoStateKind::UnregisteredBoard]).unwrap();

		// Perform a second state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable]).unwrap();

		// Ensure the state of vtxo_2 and vtxo_3 isn't modified
		let state_2 = get_vtxo_state(&tx, vtxo_2.id()).unwrap().unwrap();
		assert_eq!(state_2, VtxoState::UnregisteredBoard);
		let state_2 = get_vtxo_state(&tx, vtxo_3.id()).unwrap().unwrap();
		assert_eq!(state_2, VtxoState::UnregisteredBoard);
	}

	#[test]
	/// Each struct stored as JSON in the database should have test to check for backwards compatibility
	/// Parsing can occur either in convert.rs or this file (query.rs)
	fn test_serialised_structs() {
		// Exit state
		let serialised = r#"{"type":"start","tip_height":119}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-input-confirmation","txids":["ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de"]}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"awaiting-delta","tip_height":122,"confirmed_block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"},"spendable_height":134}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spendable","tip_height":134,"spendable_since":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"},"last_scanned_block":null}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spend-in-progress","tip_height":134,"spendable_since":{"height":134,"hash":"6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a"},"spending_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spent","tip_height":134,"txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c","block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Exit child tx origins
		let serialized = r#"{"type":"wallet","confirmed_in":null}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"wallet","confirmed_in":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"mempool","fee_rate_kwu":25000,"total_fee":27625}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();
		let serialized = r#"{"type":"block","confirmed_in":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"}}"#;
		serde_json::from_str::<ExitTxOrigin>(serialized).unwrap();

		// Movement recipient
		let serialised = r#"{"recipient":"03a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount_sat":150000}"#;
		serde_json::from_str::<MovementRecipient>(serialised).unwrap();

		// Vtxo state
		let serialised = r#""Spendable""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Spent""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""UnregisteredBoard""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();

		let serialised = r#"{"PendingLightningSend":{"invoice":{"Bolt11":"lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8"},"amount":300000}}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"PendingLightningRecv":{"payment_hash":"0000000000000000000000000000000000000000000000000000000000000000"}}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();

		let serialised = r#"{"request_policy":"0003a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount":300000,"state":"Spendable"}"#;
		serde_json::from_str::<StoredVtxoRequest>(serialised).unwrap();
	}
}
