//! SQLite persistence backend for Bark.
//!
//! This module provides a concrete implementation of the `BarkPersister` trait
//! backed by a local SQLite database. It encapsulates schema creation and
//! migrations, typed query helpers, and conversions between in-memory models
//! and their stored representations. Operations are performed using explicit
//! connections and transactions to ensure atomic updates across related tables,
//! covering wallet properties, movements, vtxos and their states, round
//! lifecycle data, Lightning receives, exit tracking, and sync metadata.

mod convert;
mod migrations;
mod query;


use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::{Amount, Txid};
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;
use log::debug;
use rusqlite::{Connection, Transaction};

use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;

use crate::{Vtxo, VtxoId, VtxoState, WalletProperties};
use crate::exit::models::ExitTxOrigin;
use crate::movement::{Movement, MovementArgs, MovementKind};
use crate::persist::models::{PendingLightningSend, LightningReceive, StoredExit};
use crate::persist::{BarkPersister, RoundStateId, StoredRoundState};
use crate::round::{RoundState, UnconfirmedRound};
use crate::vtxo_state::{VtxoStateKind, WalletVtxo, UNSPENT_STATES};

/// An implementation of the BarkPersister using rusqlite. Changes are persisted using the given
/// [PathBuf].
#[derive(Clone)]
pub struct SqliteClient {
	connection_string: PathBuf,
}

impl SqliteClient {
	/// Open a new [SqliteClient] with the given file path
	pub fn open(db_file: impl AsRef<Path>) -> anyhow::Result<SqliteClient> {
		let path = db_file.as_ref().to_path_buf();

		debug!("Opening database at {}", path.display());
		let mut conn = rusqlite::Connection::open(&path)
			.with_context(|| format!("Error connecting to database {}", path.display()))?;

		let migrations = migrations::MigrationContext::new();
		migrations.do_all_migrations(&mut conn)?;

		Ok( Self { connection_string: path })
	}

	fn connect(&self) -> anyhow::Result<Connection> {
		rusqlite::Connection::open(&self.connection_string)
			.with_context(|| format!("Error connecting to database {}", self.connection_string.display()))
	}

	/// Create a movement to link VTXOs to it
	fn create_movement(&self, tx: &Transaction, kind: MovementKind, fees: Option<Amount>) -> anyhow::Result<i32> {
		let movement_id = query::create_movement(&tx, kind, fees)?;

		Ok(movement_id)
	}

	/// Stores a movement recipient
	fn create_recipient(
		&self,
		tx: &Transaction,
		movement: i32,
		recipient: &str,
		amount: Amount,
	) -> anyhow::Result<()> {
		query::create_recipient(&tx, movement, recipient, amount)?;
		Ok(())
	}

	/// Links a VTXO to a movement and marks it as spent, so its not used for a future send
	fn mark_vtxo_as_spent(&self, tx: &Transaction, id: VtxoId, movement_id: i32) -> anyhow::Result<()> {
		query::update_vtxo_state_checked(&tx, id, VtxoState::Spent, &UNSPENT_STATES)?;
		query::link_spent_vtxo_to_movement(&tx, id, movement_id)?;
		Ok(())
	}
}

impl BarkPersister for SqliteClient {
	fn init_wallet(&self, properties: &WalletProperties) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		query::set_properties(&tx, properties)?;

		tx.commit()?;
		Ok(())
	}

	#[cfg(feature = "onchain_bdk")]
	fn initialize_bdk_wallet(&self) -> anyhow::Result<bdk_wallet::ChangeSet> {
	    let mut conn = self.connect()?;
		Ok(bdk_wallet::WalletPersister::initialize(&mut conn)?)
	}

	#[cfg(feature = "onchain_bdk")]
	fn store_bdk_wallet_changeset(&self, changeset: &bdk_wallet::ChangeSet) -> anyhow::Result<()> {
	    let mut conn = self.connect()?;
		bdk_wallet::WalletPersister::persist(&mut conn, changeset)?;
		Ok(())
	}

	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		let conn = self.connect()?;
		Ok(query::fetch_properties(&conn)?)
	}

	fn check_recipient_exists(&self, recipient: &str) -> anyhow::Result<bool> {
		let conn = self.connect()?;
		query::check_recipient_exists(&conn, recipient)
	}

	fn get_movements(&self) -> anyhow::Result<Vec<Movement>> {
		let conn = self.connect()?;
		query::get_movements(&conn)
	}

	fn register_movement(&self, movement: MovementArgs) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		let movement_id = self.create_movement(&tx, movement.kind, movement.fees)?;

		for v in movement.spends {
			self.mark_vtxo_as_spent(&tx, v.id(), movement_id)
				.context("Failed to mark vtxo as spent")?;
		}

		for (v, s) in movement.receives {
			query::store_vtxo_with_initial_state(&tx, v, movement_id, s)?;
		}

		for (recipient, amount) in movement.recipients {
			self.create_recipient(&tx, movement_id, recipient, *amount)
				.context("Failed to store change VTXOs")?
		}
		tx.commit()?;
		Ok(())
	}

	fn store_pending_board(&self, vtxo: &Vtxo, funding_tx: &bitcoin::Transaction) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_new_pending_board(&tx, vtxo, funding_tx)?;
		tx.commit()?;
		Ok(())
	}

	fn remove_pending_board(&self, vtxo_id: &VtxoId) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::remove_pending_board(&tx, vtxo_id)?;
		tx.commit()?;
		Ok(())
	}

	fn get_all_pending_boards(&self) -> anyhow::Result<Vec<VtxoId>> {
		let conn = self.connect()?;
		query::get_all_pending_boards(&conn)
	}

	fn store_round_state_lock_vtxos(&self, round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		for vtxo in round_state.participation().inputs.iter() {
			query::update_vtxo_state_checked(
				&*tx,
				vtxo.id(),
				VtxoState::Locked,
				&[VtxoStateKind::Spendable],
			)?;
		}
		let id = query::store_round_state(&tx, round_state)?;
		tx.commit()?;
		Ok(id)
	}

	fn update_round_state(&self, state: &StoredRoundState) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::update_round_state(&conn, state)?;
		Ok(())
	}

	fn remove_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::remove_round_state(&conn, round_state.id)?;
		Ok(())
	}

	fn load_round_states(&self) -> anyhow::Result<Vec<StoredRoundState>> {
		let conn = self.connect()?;
		query::load_round_states(&conn)
	}

	fn store_recovered_round(&self, round: &UnconfirmedRound) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_recovered_past_round(&conn, round)
	}

	fn remove_recovered_round(&self, funding_txid: Txid) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::remove_recovered_past_round(&conn, funding_txid)
	}

	fn load_recovered_rounds(&self) -> anyhow::Result<Vec<UnconfirmedRound>> {
		let conn = self.connect()?;
		query::load_recovered_past_rounds(&conn)
	}

	fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_wallet_vtxo_by_id(&conn, id)
	}

	fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_all_vtxos(&conn)
	}

	/// Get all VTXOs that are in one of the provided states
	fn get_vtxos_by_state(&self, state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>> {
		let conn = self.connect()?;
		query::get_vtxos_by_state(&conn, state)
	}

	fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		let conn = self.connect()?;
		let state : Option<VtxoState> = query::get_vtxo_state(&conn, id)?;
		let result = state.map(|s| s == VtxoState::Spent).unwrap_or(false);
		Ok(result)
	}

	fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let mut conn = self.connect()?;
		let tx = conn.transaction().context("Failed to start transaction")?;
		let result = query::delete_vtxo(&tx, id);
		tx.commit().context("Failed to commit transaction")?;
		result
	}

	fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_vtxo_key(&conn, index, public_key)
	}

	fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>> {
		let conn = self.connect()?;
		query::get_last_vtxo_key_index(&conn)
	}

	fn get_public_key_idx(&self, public_key: &PublicKey) -> anyhow::Result<Option<u32>> {
		let conn = self.connect()?;
		query::get_public_key_idx(&conn, public_key)
	}

	/// Store a lightning receive
	fn store_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
		invoice: &Bolt11Invoice,
		htlc_recv_cltv_delta: BlockDelta,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_lightning_receive(&conn, payment_hash, preimage, invoice, htlc_recv_cltv_delta)?;
		Ok(())
	}

	fn store_new_pending_lightning_send(&self, invoice: &Invoice, amount: &Amount, vtxos: &[VtxoId]) -> anyhow::Result<PendingLightningSend> {
		let conn = self.connect()?;
		query::store_new_pending_lightning_send(&conn, invoice, amount, vtxos)
	}

	fn get_all_pending_lightning_send(&self) -> anyhow::Result<Vec<PendingLightningSend>> {
		let conn = self.connect()?;
		query::get_all_pending_lightning_send(&conn)
	}

	fn remove_pending_lightning_send(&self, payment_hash: PaymentHash) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::remove_pending_lightning_send(&conn, payment_hash)?;
		Ok(())
	}

	fn get_all_pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		let conn = self.connect()?;
		query::get_all_pending_lightning_receives(&conn)
	}

	fn set_preimage_revealed(&self, payment_hash: PaymentHash) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_preimage_revealed(&conn, payment_hash)?;
		Ok(())
	}

	fn set_lightning_receive_vtxos(&self, payment_hash: PaymentHash, htlc_vtxo_ids: &[VtxoId]) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_lightning_receive_vtxos(&conn, payment_hash, htlc_vtxo_ids)?;
		Ok(())
	}

	/// Fetch a lightning receive by payment hash
	fn fetch_lightning_receive_by_payment_hash(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<LightningReceive>> {
		let conn = self.connect()?;
		query::fetch_lightning_receive_by_payment_hash(&conn, payment_hash)
	}

	fn remove_pending_lightning_receive(&self, payment_hash: PaymentHash) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::remove_pending_lightning_receive(&conn, payment_hash)?;
		Ok(())
	}

	fn store_exit_vtxo_entry(&self, exit: &StoredExit) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit_vtxo_entry(&tx, exit)?;
		tx.commit()?;
		Ok(())
	}

	fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::remove_exit_vtxo_entry(&tx, &id)?;
		tx.commit()?;
		Ok(())
	}

	fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>> {
		let conn = self.connect()?;
		query::get_exit_vtxo_entries(&conn)
	}

	fn store_exit_child_tx(
		&self,
		exit_txid: Txid,
		child_tx: &bitcoin::Transaction,
		origin: ExitTxOrigin,
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit_child_tx(&tx, exit_txid, child_tx, origin)?;
		tx.commit()?;
		Ok(())
	}

	fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(bitcoin::Transaction, ExitTxOrigin)>> {
		let conn = self.connect()?;
		query::get_exit_child_tx(&conn, exit_txid)
	}

	fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind]
	) -> anyhow::Result<WalletVtxo> {
		let conn = self.connect()?;
		query::update_vtxo_state_checked(&conn, vtxo_id, new_state, allowed_old_states)
	}
}

#[cfg(any(test, doc))]
pub mod helpers {
	use std::path::PathBuf;
	use std::str::FromStr;

	use rusqlite::Connection;

	/// Creates an in-memory sqlite connection.
	///
	/// It returns a [PathBuf] and a [Connection].
	/// The user should ensure the [Connection] isn't dropped
	/// until the test completes. If all connections are dropped during
	/// the test the entire database might be cleared.
	#[cfg(any(test, feature = "rand"))]
	pub fn in_memory_db() -> (PathBuf, Connection) {
		use rand::{distr, Rng};

		// All tests run in the same process and share the same
		// cache. To ensure that each call to `in_memory` results
		// in a new database a random file-name is generated.
		//
		// This database is deleted once all connections are dropped
		let mut rng = rand::rng();
		let filename: String = (&mut rng).sample_iter(distr::Alphanumeric)
			.take(16).map(char::from).collect();

		let connection_string = format!("file:{}?mode=memory&cache=shared", filename);
		let pathbuf = PathBuf::from_str(&connection_string).unwrap();

		let conn = Connection::open(pathbuf.clone()).unwrap();
		(pathbuf.clone(), conn)
	}
}

#[cfg(test)]
mod test {

	use bdk_wallet::chain::DescriptorExt;
	use bitcoin::bip32;

	use ark::vtxo::test::VTXO_VECTORS;

	use crate::persist::sqlite::helpers::in_memory_db;

	use super::*;

	#[test]
	fn test_add_and_retreive_vtxos() {
		let pk: PublicKey = "024b859e37a3a4b22731c9c452b1b55e17e580fb95dac53472613390b600e1e3f0".parse().unwrap();

		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let (cs, conn) = in_memory_db();
		let db = SqliteClient::open(cs).unwrap();

		db.register_movement(MovementArgs {
			kind: MovementKind::Board,
			spends: &[],
			receives: &[(&vtxo_1, VtxoState::Spendable)],
			recipients: &[],
			fees: None,
		}).unwrap();

		db.register_movement(MovementArgs {
			kind: MovementKind::Board,
			spends: &[],
			receives: &[(&vtxo_2, VtxoState::Spendable)],
			recipients: &[],
			fees: None,
		}).unwrap();

		// Check that vtxo-1 can be retrieved from the database
		let vtxo_1_db = db.get_wallet_vtxo(vtxo_1.id()).expect("No error").expect("A vtxo was found");
		assert_eq!(vtxo_1_db.vtxo, *vtxo_1);

		// Verify that vtxo 3 is not in the database
		assert!(db.get_wallet_vtxo(vtxo_3.id()).expect("No error").is_none());

		// Verify that we have two entries in the database
		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_1));
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_2));
		assert!(!vtxos.iter().any(|v| v.vtxo == *vtxo_3));

		// Verify that we can mark a vtxo as spent
		db.register_movement(MovementArgs {
			kind: MovementKind::Board,
			spends: &[&vtxo_1],
			receives: &[],
			recipients: &[
				(&pk.to_string(), Amount::from_sat(501))
			],
			fees: None
		}).unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).unwrap();
		assert_eq!(vtxos.len(), 1);

		// Add the third entry to the database
		db.register_movement(MovementArgs {
			kind: MovementKind::Board,
			spends: &[],
			receives: &[(&vtxo_3, VtxoState::Spendable)],
			recipients: &[],
			fees: None,
		}).unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_2));
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_3));

		conn.close().unwrap();
	}

	#[test]
	fn test_create_wallet_then_load() {
		let (connection_string, conn) = in_memory_db();

		let db = SqliteClient::open(connection_string).unwrap();
		let network = bitcoin::Network::Testnet;

		let seed = bip39::Mnemonic::generate(12).unwrap().to_seed("");
		let xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();

		let desc = format!("tr({}/84'/0'/0'/*)", xpriv);

		// need to call init before we call store
		let _ = db.initialize_bdk_wallet().unwrap();
		let mut created = bdk_wallet::Wallet::create_single(desc.clone())
			.network(network)
			.create_wallet_no_persist()
			.unwrap();
		db.store_bdk_wallet_changeset(&created.take_staged().unwrap()).unwrap();

		let loaded = {
			let changeset = db.initialize_bdk_wallet().unwrap();
			bdk_wallet::Wallet::load()
				.descriptor(bdk_wallet::KeychainKind::External, Some(desc.clone()))
				.extract_keys()
				.check_network(network)
				.load_wallet_no_persist(changeset)
				.unwrap()
		};

		assert!(loaded.is_some());
		assert_eq!(
			created.public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id(),
			loaded.unwrap().public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id()
		);

		// Explicitly close the connection here
		// This ensures the database isn't dropped during the test
		conn.close().unwrap();
	}
}
