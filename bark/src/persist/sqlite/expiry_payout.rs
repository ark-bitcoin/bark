//! The wallet tables of expiry payouts.
//!
//! They are created after upstream's numbered migrations and are not part of
//! them, so the wallet records the same migration versions as upstream and
//! runs every migration that upstream adds later.

use std::str::FromStr;

use anyhow::Context;
use bitcoin::secp256k1::PublicKey;
use rusqlite::{Connection, OptionalExtension};

/// The public key of the wallet's mailbox keypair.
const TABLES: &str = "
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
