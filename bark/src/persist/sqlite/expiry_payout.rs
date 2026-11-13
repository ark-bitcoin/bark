//! The wallet tables of expiry payouts.
//!
//! They are created after upstream's numbered migrations and are not part of
//! them, so the wallet records the same migration versions as upstream and
//! runs every migration that upstream adds later.

use std::str::FromStr;

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

use ark::VtxoId;

use crate::persist::sqlite::query::get_wallet_vtxo_by_id;
use crate::vtxo::{ExpiryPayoutState, WalletVtxo};

/// The expiry payout state that the server last reported for each VTXO, and
/// the public key of the wallet's mailbox keypair.
const TABLES: &str = "
	CREATE TABLE IF NOT EXISTS expiry_payout_vtxo (
		vtxo_id TEXT PRIMARY KEY,
		status TEXT NOT NULL CHECK (status IN ('pending', 'paid', 'forfeited'))
	);
	CREATE TABLE IF NOT EXISTS mailbox_key (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		mailbox_pubkey TEXT NOT NULL CHECK (length(mailbox_pubkey) = 66)
	);";

/// Create the expiry payout tables if they do not exist.
pub(crate) fn create_tables(conn: &Connection) -> anyhow::Result<()> {
	conn.execute_batch(TABLES).context("failed to create the expiry payout tables")
}

/// Store the mailbox public key, unless it is already stored. Fails if
/// another key is stored.
pub(crate) fn store_mailbox_pubkey(conn: &Connection, mailbox_pubkey: &PublicKey) -> anyhow::Result<()> {
	let query = "INSERT OR IGNORE INTO mailbox_key (id, mailbox_pubkey) VALUES (1, ?1)";
	conn.execute(query, [mailbox_pubkey.to_string()])?;
	ensure!(fetch_mailbox_pubkey(conn)?.as_ref() == Some(mailbox_pubkey),
		"another mailbox key is stored");
	Ok(())
}

pub(crate) fn fetch_mailbox_pubkey(conn: &Connection) -> anyhow::Result<Option<PublicKey>> {
	let query = "SELECT mailbox_pubkey FROM mailbox_key WHERE id = 1";
	let mailbox_pubkey = conn.query_row(query, [], |row| row.get::<_, String>(0)).optional()?;
	mailbox_pubkey.map(|key| PublicKey::from_str(&key).context("invalid mailbox public key"))
		.transpose()
}

/// Record the expiry payout state of a VTXO and mark the VTXO spent, unless
/// the wallet exited it.
pub(crate) fn set_vtxo_expiry_payout_state(
	tx: &Transaction,
	vtxo_id: VtxoId,
	payout_state: ExpiryPayoutState,
) -> anyhow::Result<WalletVtxo> {
	let vtxo = get_wallet_vtxo_by_id(tx, vtxo_id)?.context("the VTXO is not stored")?;

	let query = "INSERT OR REPLACE INTO expiry_payout_vtxo (vtxo_id, status) VALUES (?1, ?2)";
	tx.execute(query, params![vtxo_id.to_string(), payout_state.as_str()])?;

	let state = ExpiryPayoutState::vtxo_state(&vtxo.state);
	if state != vtxo.state {
		let query = "INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state) VALUES (?1, ?2, ?3)";
		let state_blob = serde_json::to_vec(&state)?;
		tx.execute(query, params![vtxo_id.to_string(), state.kind().as_str(), state_blob])?;
	}

	get_wallet_vtxo_by_id(tx, vtxo_id)?.context("the VTXO is not stored")
}

pub(crate) fn delete_vtxo_expiry_payout_state(tx: &Transaction, vtxo_id: VtxoId) -> anyhow::Result<()> {
	tx.execute("DELETE FROM expiry_payout_vtxo WHERE vtxo_id = ?1", [vtxo_id.to_string()])?;
	Ok(())
}
