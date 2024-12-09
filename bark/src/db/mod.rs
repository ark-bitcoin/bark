mod convert;
mod migrations;
mod query;

use std::path::PathBuf;

use anyhow::Context;
use rusqlite::Connection;
use bdk_wallet::{ChangeSet, WalletPersister};
use bitcoin::Amount;

use crate::{exit::Exit, ReadOnlyConfig, Config, Vtxo, VtxoId, VtxoState};

#[derive(Clone)]
pub struct Db {
	connection_string: PathBuf,
}

impl Db {
	pub fn open(path: PathBuf) -> anyhow::Result<Db> {
		info!("Opening database at {}", path.display());
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

	pub (crate) fn init_config(&self, config: &Config, rd_config: &ReadOnlyConfig) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_config(&conn, config, rd_config)?;
		Ok(())
	}

	pub fn write_config(&self, pub_config: &Config) -> anyhow::Result<()> {
		let conn = self.connect()?;
		let (_, prv_config) = query::fetch_config(&conn)?.context("Config unexpectedly missing")?;
		query::store_config(&conn, pub_config, &prv_config)?;
		Ok(())
	}

	pub fn read_config(&self) -> anyhow::Result<Option<(Config, ReadOnlyConfig)>> {
		let conn = self.connect()?;
		Ok(query::fetch_config(&conn)?)
	}

	/// Stores a vtxo in the database
	pub fn store_vtxo(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		// TODO: Use a better name.In most cases we don't want new vtxo's to get the state
		// ready
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_vtxo_with_initial_state(&tx, vtxo, VtxoState::Ready)?;
		tx.commit()?;
		Ok(())
	}

	pub fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let conn = self.connect()?;
		query::get_vtxo_by_id(&conn, id)
	}

	pub fn get_all_spendable_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.connect()?;
		query::get_vtxos_by_state(&conn, VtxoState::Ready)
	}

	/// Get the soonest-expiring vtxos with total value at least `min_value`.
	pub fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.connect()?;
		query::get_expiring_vtxos(&conn, min_value)
	}

	pub fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let mut conn = self.connect()?;
		let tx = conn.transaction().context("Failed to start transaction")?;
		let result = query::delete_vtxo(&tx, id);
		tx.commit().context("Failed to commit transaction")?;
		result
	}

	/// Store the ongoing exit process.
	pub fn store_exit(&self, exit: &Exit) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit(&tx, exit)?;
		tx.commit()?;
		Ok(())
	}

	/// Fetch the ongoing exit process.
	pub fn fetch_exit(&self) -> anyhow::Result<Option<Exit>> {
		let conn = self.connect()?;
		query::fetch_exit(&conn)
	}

	pub fn get_last_ark_sync_height(&self) -> anyhow::Result<u32> {
		let conn = self.connect()?;
		query::get_last_ark_sync_height(&conn)
	}

	pub fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_last_ark_sync_height(&conn, height)
	}

	pub fn mark_vtxo_as_spent(&self, id: VtxoId) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::update_vtxo_state(&conn, id, VtxoState::Spent)
	}

	pub fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		let conn = self.connect()?;
		let state : Option<VtxoState> = query::get_vtxo_state(&conn, id)?;
		let result = state.map(|s| s == VtxoState::Spent).unwrap_or(false);
		Ok(result)
	}
}

impl WalletPersister for Db {
	type Error = rusqlite::Error;

	fn initialize(persister: &mut Self) -> Result<ChangeSet, Self::Error> {
		let mut conn = rusqlite::Connection::open(&persister.connection_string)?;
		rusqlite::Connection::initialize(&mut conn)
	}

	fn persist(persister: &mut Self, changeset: &ChangeSet) -> Result<(), Self::Error> {
		let mut conn = rusqlite::Connection::open(&persister.connection_string)?;
		rusqlite::Connection::persist(&mut conn, changeset)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;

	use bdk_wallet::chain::DescriptorExt;
	use bitcoin::bip32;
	use rand::{Rng, distributions::Alphanumeric};

	use ark::{BaseVtxo, VtxoSpec};

	use super::*;


	/// Creates an in-memory sqlite connection
	/// 
	/// It returns a [PathBuf] and a [Connection].
	/// The user should ensure the [Connection] isn't dropped
	/// until the test completes. If all connections are dropped during
	/// the test the entire database might be cleared.
	fn in_memory() -> (PathBuf, Connection) {

		// All tests run in the same process and share the same
		// cache. To ensure that each call to `in_memory` results
		// in a new database a random file-name is generated.
		//
		// This database is deleted once all connections are dropped
		let mut rng = rand::thread_rng();
		let filename: String = (&mut rng).sample_iter(Alphanumeric)
			.take(16).map(char::from).collect();

		let connection_string = format!("file:{}?mode=memory&cache=shared", filename);
		let pathbuf = PathBuf::from_str(&connection_string).unwrap();

		let conn = Connection::open(pathbuf.clone()).unwrap();
		(pathbuf.clone(), conn)
	}

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

		let (cs, conn) = in_memory();
		let db = Db::open(cs).unwrap();
		db.store_vtxo(&vtxo_1).unwrap();
		db.store_vtxo(&vtxo_2).unwrap();

		// Check that vtxo-1 can be retrieved from the database
		let vtxo_1_db = db.get_vtxo(vtxo_1.id()).expect("No error").expect("A vtxo was found");
		assert_eq!(vtxo_1_db, vtxo_1);

		// Verify that vtxo 3 is not in the database
		assert!(db.get_vtxo(vtxo_3.id()).expect("No error").is_none());

		// Verify that we have two entries in the database
		let vtxos = db.get_all_spendable_vtxos().unwrap();
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

		conn.close().unwrap();
	}

	#[test]
	fn test_create_wallet_then_load() {
		let (connection_string, conn) = in_memory();

		let mut db = Db::open(connection_string).unwrap();
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

		// Explicitly close the connection here
		// This ensures the database isn't dropped during the test
		conn.close().unwrap();
	}
}
