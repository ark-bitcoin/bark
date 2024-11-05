mod convert;
mod migrations;
mod query;

use std::{path::Path, rc::Rc};
use std::sync::RwLock;

use anyhow::Context;
use bdk_wallet::{rusqlite::Connection, ChangeSet, WalletPersister};
use bitcoin::Amount;

use crate::{Vtxo, VtxoId, VtxoState, exit::Exit};

#[derive(Clone)]
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
	conn: Rc<RwLock<Connection>>
}


impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		info!("Opening database at {}", path.display());
		let mut conn = rusqlite::Connection::open(path)
			.with_context(|| format!("Error connecting to database {}", path.display()))?;

		let migrations = migrations::MigrationContext::new();
		migrations.do_all_migrations(&mut conn)?;

		Ok( Self { conn: Rc::new(RwLock::new(conn)) })
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
		let result = state.map(|s| s == VtxoState::Spent).unwrap_or(false);
		Ok(result)
	}
}

impl WalletPersister for Db {
	type Error = rusqlite::Error;

	fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
		let mut conn = persister.conn.write().unwrap();
		rusqlite::Connection::initialize(&mut *conn)
	}

	fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
		let mut conn = persister.conn.write().unwrap();
		rusqlite::Connection::persist(&mut *conn, changeset)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use ark::{BaseVtxo, VtxoSpec};
	use bdk_wallet::chain::DescriptorExt;
	use bitcoin::bip32;

	#[test]
	fn test_add_and_retreive_vtxos() {
		// We can use stupid data here.
		// If the vtxo/signatures are invalid the database does't care
		// It is the job of the application to worry about this
		let pk = "024b859e37a3a4b22731c9c452b1b55e17e580fb95dac53472613390b600e1e3f0".parse().unwrap();
		let point_1 = "0000000000000000000000000000000000000000000000000000000000000000:1".parse().unwrap();
		let point_2 = "0000000000000000000000000000000000000000000000000000000000000000:2".parse().unwrap();
		let point_3 = "0000000000000000000000000000000000000000000000000000000000000000:3".parse().unwrap();
		let sig = "cc8b93e9f6fbc2506bb85ae8bbb530b178daac49704f5ce2e3ab69c266fd59320b28d028eef212e3b9fdc42cfd2e0760a0359d3ea7d2e9e8cfe2040e3f1b71ea".parse().unwrap();

		let vtxo_1 = Vtxo::Onboard {
			reveal_tx_signature: sig,
			base: BaseVtxo {
				utxo: point_1,
				spec: VtxoSpec {
					user_pubkey: pk,
					asp_pubkey: pk,
					expiry_height: 1001,
					exit_delta: 40,
					amount: Amount::from_sat(500)
				},
			},
		};

		let vtxo_2 = Vtxo::Onboard {
			reveal_tx_signature: sig,
			base: BaseVtxo {
				utxo: point_2,
				spec: VtxoSpec {
					user_pubkey: pk,
					asp_pubkey: pk,
					expiry_height: 1002,
					exit_delta: 40,
					amount: Amount::from_sat(500)
				},
			},
		};

		let vtxo_3 = Vtxo::Onboard {
			reveal_tx_signature: sig,
			base: BaseVtxo {
				utxo: point_3,
				spec: VtxoSpec {
					user_pubkey: pk,
					asp_pubkey: pk,
					expiry_height: 1003,
					exit_delta: 40,
					amount: Amount::from_sat(500)
				},
			},
		};


		let db = Db::open(Path::new(":memory:")).unwrap();
		db.store_vtxo(&vtxo_1).unwrap();
		db.store_vtxo(&vtxo_2).unwrap();

		// Check that vtxo-1 can be retrieved from the database
		let vtxo_1_db = db.get_vtxo(vtxo_1.id()).expect("No error").expect("A vtxo was found");
		assert_eq!(vtxo_1_db, vtxo_1);

		// Verify that vtxo 3 is not in the database
		assert!(db.get_vtxo(vtxo_3.id()).expect("No error").is_none());

		// Verify that we have two entries in the database
		let vtxos = db.get_all_vtxos().unwrap();
		assert_eq!(vtxos.len(), 2);
		assert!(vtxos.contains(&vtxo_1));
		assert!(vtxos.contains(&vtxo_2));
		assert!(! vtxos.contains(&vtxo_3));

		// Add the thrid entry to the database
		db.store_vtxo(&vtxo_3).unwrap();

		// Get expiring vtxo's
		// Matches exactly the first vtxo
		let vs = db.get_expiring_vtxos(Amount::from_sat(500)).unwrap();
		assert_eq!(vs, [vtxo_1.clone()]);

		// Overshoots the first vtxo by one sat
		let vs = db.get_expiring_vtxos(Amount::from_sat(501)).unwrap();
		assert_eq!(vs, [vtxo_1.clone(), vtxo_2.clone()]);

		// Verify that we can mark a vtxo as spent
		db.mark_vtxo_as_spent(vtxo_1.id()).unwrap();
		assert!(db.has_spent_vtxo(vtxo_1.id()).unwrap());
		assert!(! db.has_spent_vtxo(vtxo_2.id()).unwrap());
		assert!(! db.has_spent_vtxo(vtxo_3.id()).unwrap());

		// The first vtxo has been spent
		// It shouldn't be used for coin selection
		let vs = db.get_expiring_vtxos(Amount::from_sat(501)).unwrap();
		assert_eq!(vs, [vtxo_2.clone(), vtxo_3.clone()]);
	}

	#[test]
	fn test_create_wallet_then_load() {
		let mut db = Db::open(Path::new(":memory:")).unwrap();
		let network = bitcoin::Network::Testnet;

		let seed = bip39::Mnemonic::generate(12).unwrap().to_seed("");
		let xpriv = bip32::Xpriv::new_master(network, &seed).unwrap();

		let edesc = format!("tr({}/84'/0'/0'/0/*)", xpriv);
		let idesc = format!("tr({}/84'/0'/0'/1/*)", xpriv);

		let created = bdk_wallet::Wallet::create(edesc.clone(), idesc.clone())
			.network(network)
			.create_wallet(&mut db)
			.unwrap();

		let loaded = bdk_wallet::Wallet::load()
			.descriptor(bdk_wallet::KeychainKind::External, Some(edesc.clone()))
			.descriptor(bdk_wallet::KeychainKind::Internal, Some(idesc.clone()))
			.extract_keys()
			.check_network(network)
			.load_wallet(&mut db)
			.unwrap();

		assert!(loaded.is_some());
		assert_eq!(
			created.public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id(), 
			loaded.unwrap().public_descriptor(bdk_wallet::KeychainKind::External).descriptor_id()
		);
	}
}
