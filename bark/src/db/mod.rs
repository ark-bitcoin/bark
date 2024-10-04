mod convert;
mod migrations;
mod query;


use std::path::Path;
use std::sync::RwLock;

use anyhow::Context;
use bitcoin::Amount;
use rusqlite::Connection;

use crate::{Vtxo, VtxoId, VtxoState, exit::Exit};

pub struct Db {
	// The name RwLock might falsely imply this lock is used for reading
	// and writing. This is not the case
	//
	// A single sqlite connection supports concurrent reading and writing.
	// However, it only allows one concurrent transaction.
	//
	// You should use the `read`-lock if you want to make a query
	// You should use the `write`-lock if you want to make a transaction
	//
	// The compiler is nice and will have your back on this
	conn: RwLock<Connection>
}


impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		info!("Opening database at {}", path.display());
		let mut conn = rusqlite::Connection::open(path)
			.with_context(|| format!("Error connecting to database {}", path.display()))?;

		let migrations = migrations::MigrationContext::new();
		migrations.do_all_migrations(&mut conn)?;

		Ok( Self { conn: RwLock::new(conn) })
	}

	/// Stores a vtxo in the database
	pub fn store_vtxo(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		// TODO: Use a better name.In most cases we don't want new vtxo's to get the state
		// ready
		let mut conn = self.conn.write().unwrap();
		let tx = conn.transaction()?;
		query::store_vtxo_with_initial_state(&tx, vtxo, VtxoState::Ready)?;
		tx.commit()?;
		Ok(())
	}

	pub fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let conn = self.conn.read().unwrap();
		query::get_vtxo_by_id(&conn, id)
	}

	pub fn get_all_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		// TODO: This is not a proper name as this function doesn't 
		// return spent vtxo's. 
		let conn = self.conn.read().unwrap();
		query::get_vtxos_by_state(&conn, VtxoState::Ready)
	}

	/// Get the soonest-expiring vtxos with total value at least `min_value`.
	pub fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.conn.read().unwrap();
		query::get_expiring_vtxos(&conn, min_value)
	}

	pub fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let mut conn = self.conn.write().unwrap();
		let tx = conn.transaction().context("Failed to start transaction")?;
		let result = query::delete_vtxo(&tx, id);
		tx.commit().context("Failed to commit transaction")?;
		result
	}

	/// Store the ongoing exit process.
	pub fn store_exit(&self, exit: &Exit) -> anyhow::Result<()> {
		let mut conn = self.conn.write().unwrap();
		let tx = conn.transaction()?;
		query::store_exit(&tx, exit)?;
		tx.commit()?;
		Ok(())
	}

	/// Fetch the ongoing exit process.
	pub fn fetch_exit(&self) -> anyhow::Result<Option<Exit>> {
		let conn = self.conn.read().unwrap();
		query::fetch_exit(&conn)
	}

	pub fn get_last_ark_sync_height(&self) -> anyhow::Result<u32> {
		let conn = self.conn.read().unwrap();
		query::get_last_ark_sync_height(&conn)
	}

	pub fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()> {
		let conn = self.conn.read().unwrap();
		query::store_last_ark_sync_height(&conn, height)
	}

	pub fn mark_vtxo_as_spent(&self, id: VtxoId) -> anyhow::Result<()> {
		let conn = self.conn.read().unwrap();
		query::update_vtxo_state(&conn, id, VtxoState::Spent)
	}

	pub fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		let conn = self.conn.read().unwrap();
		let state : Option<VtxoState> = query::get_vtxo_state(&conn, id)?;
		let result = state.map(|s| s == VtxoState::Ready).unwrap_or(false);
		Ok(result)
	}
}
