mod migrations;

use std::path::Path;

use bitcoin::Amount;

use crate::{Vtxo, VtxoId, exit::Exit};

pub struct Db {}

impl Db {
	pub fn open(path: &Path) -> anyhow::Result<Db> {
		todo!("Implement")
	}

	pub fn store_vtxo(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		todo!("implement")
}

	pub fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		todo!("Implement")
}

	pub fn get_all_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		todo!("Implement")
	}

	/// Get the soonest-expiring vtxos with total value at least `min_value`.
	pub fn get_expiring_vtxos(&self, min_value: Amount) -> anyhow::Result<Vec<Vtxo>> {
		todo!("Implement")
	}

	pub fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>> {
		todo!("Impleemnt")
	}

	/// Store the ongoing exit process.
	pub fn store_exit(&self, exit: &Exit) -> anyhow::Result<()> {
		todo!("Implement")
	}

	/// Fetch the ongoing exit process.
	pub fn fetch_exit(&self) -> anyhow::Result<Option<Exit>> {
		todo!("implement")
	}

	pub fn get_last_ark_sync_height(&self) -> anyhow::Result<u32> {
		todo!("implement")
	}

	pub fn store_last_ark_sync_height(&self, height: u32) -> anyhow::Result<()> {
		todo!("implement")
	}

	pub fn mark_vtxo_as_spent(&self, id: VtxoId) -> anyhow::Result<()> {
		todo!("implement")
	}

	pub fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool> {
		todo!("implement")
	}
}

