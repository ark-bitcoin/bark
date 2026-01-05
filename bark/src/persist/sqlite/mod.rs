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
use chrono::DateTime;
use lightning_invoice::Bolt11Invoice;
use log::debug;
use rusqlite::Connection;

use ark::lightning::{Invoice, PaymentHash, Preimage};
use bitcoin_ext::BlockDelta;

use crate::{Vtxo, VtxoId, WalletProperties};
use crate::exit::ExitTxOrigin;
use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem, PaymentMethod};
use crate::persist::{BarkPersister, RoundStateId, StoredRoundState};
use crate::persist::models::{LightningReceive, LightningSend, PendingBoard, StoredExit};
use crate::round::RoundState;
use crate::vtxo::{VtxoState, VtxoStateKind, WalletVtxo};

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

	fn check_recipient_exists(&self, recipient: &PaymentMethod) -> anyhow::Result<bool> {
		let conn = self.connect()?;
		query::check_recipient_exists(&conn, recipient)
	}

	fn create_new_movement(&self,
		status: MovementStatus,
		subsystem: &MovementSubsystem,
		time: DateTime<chrono::Local>,
	) -> anyhow::Result<MovementId> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		let movement_id = query::create_new_movement(&tx, status, subsystem, time)?;
		tx.commit()?;
		Ok(movement_id)
	}

	fn update_movement(&self, movement: &Movement) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::update_movement(&tx, movement)?;
		tx.commit()?;
		Ok(())
	}

	fn get_movement_by_id(&self, movement_id: MovementId) -> anyhow::Result<Movement> {
		let conn = self.connect()?;
		query::get_movement_by_id(&conn, movement_id)
	}

	fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>> {
		let conn = self.connect()?;
		query::get_all_movements(&conn)
	}

	fn store_pending_board(
		&self,
		vtxo: &Vtxo,
		funding_tx: &bitcoin::Transaction,
		movement_id: MovementId,
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_new_pending_board(&tx, vtxo, funding_tx, movement_id)?;
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

	fn get_all_pending_board_ids(&self) -> anyhow::Result<Vec<VtxoId>> {
		let conn = self.connect()?;
		query::get_all_pending_boards_ids(&conn)
	}

	fn get_pending_board_by_vtxo_id(&self, vtxo_id: VtxoId) -> anyhow::Result<Option<PendingBoard>> {
		let conn = self.connect()?;
		query::get_pending_board_by_vtxo_id(&conn, vtxo_id)
	}

	fn store_round_state_lock_vtxos(&self, round_state: &RoundState) -> anyhow::Result<RoundStateId> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		for vtxo in round_state.participation().inputs.iter() {
			query::update_vtxo_state_checked(
				&*tx,
				vtxo.id(),
				VtxoState::Locked { movement_id: round_state.movement_id },
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

	fn store_vtxos(
		&self,
		vtxos: &[(&Vtxo, &VtxoState)],
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		for (vtxo, state) in vtxos {
			query::store_vtxo_with_initial_state(&tx, vtxo, state)?;
		}
		tx.commit()?;
		Ok(())
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
		query::store_lightning_receive(
			&conn, payment_hash, preimage, invoice, htlc_recv_cltv_delta,
		)?;
		Ok(())
	}

	fn store_new_pending_lightning_send(
		&self,
		invoice: &Invoice,
		amount: &Amount,
		vtxos: &[VtxoId],
		movement_id: MovementId,
	) -> anyhow::Result<LightningSend> {
		let conn = self.connect()?;
		query::store_new_pending_lightning_send(&conn, invoice, amount, vtxos, movement_id)
	}

	fn get_all_pending_lightning_send(&self) -> anyhow::Result<Vec<LightningSend>> {
		let conn = self.connect()?;
		query::get_all_pending_lightning_send(&conn)
	}

	fn finish_lightning_send(
		&self,
		payment_hash: PaymentHash,
		preimage: Option<Preimage>,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::finish_lightning_send(&conn, payment_hash, preimage)
	}

	fn remove_lightning_send(&self, payment_hash: PaymentHash) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::remove_lightning_send(&conn, payment_hash)?;
		Ok(())
	}

	fn get_lightning_send(&self, payment_hash: PaymentHash) -> anyhow::Result<Option<LightningSend>> {
		let conn = self.connect()?;
		query::get_lightning_send(&conn, payment_hash)
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

	fn update_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		htlc_vtxo_ids: &[VtxoId],
		movement_id: MovementId,
	) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::update_lightning_receive(&conn, payment_hash, htlc_vtxo_ids, movement_id)?;
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

	fn finish_pending_lightning_receive(&self, payment_hash: PaymentHash) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::finish_pending_lightning_receive(&conn, payment_hash)?;
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
	use bitcoin::bip32;

	use ark::vtxo::test::VTXO_VECTORS;

	use crate::{persist::sqlite::helpers::in_memory_db, vtxo::VtxoState};

	use super::*;

	#[test]
	fn test_add_and_retrieve_vtxos() {
		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let (cs, conn) = in_memory_db();
		let db = SqliteClient::open(cs).unwrap();

		db.store_vtxos(&[
			(vtxo_1, &VtxoState::Spendable), (vtxo_2, &VtxoState::Spendable)
		]).unwrap();

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
		db.update_vtxo_state_checked(
			vtxo_1.id(), VtxoState::Spent, &VtxoStateKind::UNSPENT_STATES,
		).unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).unwrap();
		assert_eq!(vtxos.len(), 1);

		// Add the third entry to the database
		db.store_vtxos(&[(vtxo_3, &VtxoState::Spendable)]).unwrap();

		let vtxos = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_2));
		assert!(vtxos.iter().any(|v| v.vtxo == *vtxo_3));

		conn.close().unwrap();
	}

	#[test]
	#[cfg(feature = "onchain_bdk")]
	fn test_create_wallet_then_load() {
		use bdk_wallet::chain::DescriptorExt;

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
