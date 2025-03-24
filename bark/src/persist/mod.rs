pub mod sqlite;

use ark::{Vtxo, VtxoId};
use bdk_wallet::WalletPersister;
use bitcoin::{secp256k1::PublicKey, Amount};

use crate::{exit::ExitIndex, movement::{Movement, MovementArgs}, Config, Pagination, WalletProperties};

pub trait BarkPersister: Clone + WalletPersister {
	/// Initialise wallet in the database
	///
	/// Will fail after first call
	fn init_wallet(&self, config: &Config, properties: &WalletProperties) -> anyhow::Result<()>;

	fn write_config(&self, config: &Config) -> anyhow::Result<()>;
	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>>;
	fn read_config(&self) -> anyhow::Result<Option<Config>>;

	/// Returns a list of movements matching provided destination
	fn get_all_movements_by_destination(&self, destination: &str) -> anyhow::Result<Vec<Movement>>;
	/// Returns a paginated list of movements
	fn get_paginated_movements(&self, pagination: Pagination) -> anyhow::Result<Vec<Movement>>;
	/// Register a movement
	fn register_movement<'a, S, R>(
		&self,
		movement: MovementArgs<'a, S, R>
	) -> anyhow::Result<()>
		where
			S: IntoIterator<Item = &'a Vtxo>,
			R: IntoIterator<Item = &'a Vtxo>;

	/// Fetch a VTXO by id in the database
	fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>>;
	/// Fetch all currently spendable VTXOs in the database
	fn get_all_spendable_vtxos(&self) -> anyhow::Result<Vec<Vtxo>>;
	/// Get the soonest-expiring vtxos with total value at least `min_value`.
	fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>>;
	/// Remove a VTXO from the database
	fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>>;
	/// Check whether a VTXO has been spent already or not
	fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool>;

	/// Store a newly revealed index
	fn store_vtxo_key_index(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()>;
	/// Get last revealed index
	fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>>;
	/// Get index of vtxo key
	fn get_vtxo_key_index(&self, vtxo: &Vtxo) -> anyhow::Result<u32>;
	/// Checks if provided public key exists in the database,
	/// meaning that it is owned by the wallet
	fn check_vtxo_key_exists(&self, public_key: &PublicKey) -> anyhow::Result<bool>;

	/// Store the ongoing exit process.
	fn store_exit(&self, exit: &ExitIndex) -> anyhow::Result<()>;
	/// Fetch an ongoing exit process.
	fn fetch_exit(&self) -> anyhow::Result<Option<ExitIndex>>;

	fn get_last_ark_sync_height(&self) -> anyhow::Result<u32>;
	fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()>;
}
