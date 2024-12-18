mod convert;
mod migrations;
mod query;

use std::path::PathBuf;

use anyhow::Context;
use ark::Movement;
use rusqlite::{Connection, Transaction};
use bdk_wallet::{ChangeSet, WalletPersister};
use bitcoin::Amount;

use crate::{exit::ExitIndex, persist::BarkPersister, Config, Pagination, Vtxo, VtxoId, VtxoState, WalletProperties};

#[derive(Clone)]
pub struct SqliteClient {
	connection_string: PathBuf,
}

impl SqliteClient {
	pub fn open(path: PathBuf) -> anyhow::Result<SqliteClient> {
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

	/// Create a movement to link VTXOs to it
	fn create_movement(&self, tx: &Transaction, fees: Option<Amount>, destination: Option<String>) -> anyhow::Result<i32> {
		let movement_id = query::create_movement(&tx, fees, destination)?;

		Ok(movement_id)
	}

	/// Stores a vtxo in the database
	fn store_vtxo(&self, tx: &Transaction, vtxo: &Vtxo, movement_id: i32) -> anyhow::Result<()> {
		// TODO: Use a better name.In most cases we don't want new vtxo's to get the state
		// ready
		query::store_vtxo_with_initial_state(&tx, vtxo, movement_id, VtxoState::Ready)?;

		Ok(())
	}

	/// Links a VTXO to a movement and marks it as spent, so its not used for a future send
	fn mark_vtxo_as_spent(&self, tx: &Transaction, id: VtxoId, movement_id: i32) -> anyhow::Result<()> {
		query::update_vtxo_state(&tx, id, VtxoState::Spent)?;
		query::link_spent_vtxo_to_movement(&tx, id, movement_id)?;
		Ok(())
	}
}


impl BarkPersister for SqliteClient {
	fn init_wallet(&self, config: &Config, properties: &WalletProperties) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		query::set_properties(&tx, properties)?;
		query::set_config(&tx, config)?;

		tx.commit()?;
		Ok(())
	}

	fn write_config(&self, config: &Config) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::set_config(&conn, config)?;
		Ok(())
	}
	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>> {
		let conn = self.connect()?;
		Ok(query::fetch_properties(&conn)?)
	}
	fn read_config(&self) -> anyhow::Result<Option<Config>> {
		let conn = self.connect()?;
		Ok(query::fetch_config(&conn)?)
	}

	fn list_movements(&self, pagination: Pagination) -> anyhow::Result<Vec<Movement>> {
		let conn = self.connect()?;
		query::get_paginated_movements(&conn, pagination)
	}

	fn register_receive(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		let movement_id = self.create_movement(&tx, None, None)?;
		query::store_vtxo_with_initial_state(&tx, vtxo, movement_id, VtxoState::Ready)?;

		tx.commit()?;
		Ok(())
	}

	fn register_send<'a>(
		&self,
		vtxos: impl IntoIterator<Item = &'a Vtxo>,
		destination: String,
		change: Option<&Vtxo>,
		fees: Option<Amount>
	) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		let movement_id = self.create_movement(&tx, fees, Some(destination))?;

		if let Some(change_vtxo) = change {
			self.store_vtxo(&tx, change_vtxo, movement_id)
				.context("Failed to store change VTXOs")?
		}

		for v in vtxos {
			self.mark_vtxo_as_spent(&tx, v.id(), movement_id).context("Failed to mark vtxo as spent")?;
		}

		tx.commit()?;
		Ok(())
	}

	fn register_refresh(&self, input_vtxos: &[Vtxo], output_vtxos: &[Vtxo]) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;

		let sent_amount = input_vtxos.iter().fold(Amount::ZERO, |acc, v| acc + v.amount());
		let received_amount = output_vtxos.iter().fold(Amount::ZERO, |acc, v| acc + v.amount());

		// This works as long as wallet owns all inputs and all outputs of the in-round send (refresh)
		let fees = sent_amount - received_amount;
		let movement_id = self.create_movement(&tx, Some(fees), None)?;

		// Then add our new vtxo(s) by just checking all vtxos that might be ours.
		for v in output_vtxos {
			self.store_vtxo(&tx, &v, movement_id)
				.context("Failed to store new vtxo")?;
		}

		// And mark input vtxos as spent
		for v in input_vtxos {
			self.mark_vtxo_as_spent(&tx, v.id(), movement_id)
				.context("Failed to mark vtxo as spent")?;
		}

		tx.commit()?;
		Ok(())
	}
	fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		let conn = self.connect()?;
		query::get_vtxo_by_id(&conn, id)
	}

	fn get_all_spendable_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.connect()?;
		query::get_vtxos_by_state(&conn, VtxoState::Ready)
	}

	/// Get the soonest-expiring vtxos with total value at least `min_value`.
	fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.connect()?;
		query::get_expiring_vtxos(&conn, min_value)
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

	/// Store the ongoing exit process.
	fn store_exit(&self, exit: &ExitIndex) -> anyhow::Result<()> {
		let mut conn = self.connect()?;
		let tx = conn.transaction()?;
		query::store_exit(&tx, exit)?;
		tx.commit()?;
		Ok(())
	}
	/// Fetch the ongoing exit process.
	fn fetch_exit(&self) -> anyhow::Result<Option<ExitIndex>> {
		let conn = self.connect()?;
		query::fetch_exit(&conn)
	}

	fn get_last_ark_sync_height(&self) -> anyhow::Result<u32> {
		let conn = self.connect()?;
		query::get_last_ark_sync_height(&conn)
	}

	fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()> {
		let conn = self.connect()?;
		query::store_last_ark_sync_height(&conn, height)
	}
}


impl WalletPersister for SqliteClient {
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
		let db = SqliteClient::open(cs).unwrap();
		db.register_receive(&vtxo_1).unwrap();
		db.register_receive(&vtxo_2).unwrap();

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

		// Add the third entry to the database
		db.register_receive(&vtxo_3).unwrap();

		// Get expiring vtxo's
		// Matches exactly the first vtxo
		let vs = db.get_expiring_vtxos(Amount::from_sat(500)).unwrap();
		assert_eq!(vs, [vtxo_1.clone()]);

		// Overshoots the first vtxo by one sat
		let vs = db.get_expiring_vtxos(Amount::from_sat(501)).unwrap();
		assert_eq!(vs, [vtxo_1.clone(), vtxo_2.clone()]);

		// Verify that we can mark a vtxo as spent
		db.register_send(&vec![vtxo_1.clone()], pk.to_string(), None, None).unwrap();
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

		let mut db = SqliteClient::open(connection_string).unwrap();
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
