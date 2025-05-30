pub mod sqlite;

use ark::{Vtxo, VtxoId};
use bdk_wallet::ChangeSet;
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::BlockHeight;

use crate::{exit::ExitIndex, vtxo_state::VtxoState, Config, KeychainKind, Movement, MovementArgs, OffchainOnboard, OffchainPayment, Pagination, WalletProperties};


pub trait BarkPersister: Send + Sync + 'static {
	/// Initialise wallet in the database
	///
	/// Will fail after first call
	fn init_wallet(&self, config: &Config, properties: &WalletProperties) -> anyhow::Result<()>;

	/// Initialize the BDK wallet and load the full existing ChangeSet.
	///
	/// This function must be called before any new changeset is stored.
	fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet>;
	/// Store the incremental changeset of the BDK wallet.
	fn store_bdk_wallet_changeset(&self, changeset: &ChangeSet) -> anyhow::Result<()>;

	fn write_config(&self, config: &Config) -> anyhow::Result<()>;
	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>>;
	fn read_config(&self) -> anyhow::Result<Option<Config>>;

	/// Check if given recipient exists in the database
	fn check_recipient_exists(&self, recipient: &str) -> anyhow::Result<bool>;
	/// Returns a paginated list of movements
	fn get_paginated_movements(&self, pagination: Pagination) -> anyhow::Result<Vec<Movement>>;
	/// Register a movement
	fn register_movement(&self, movement: MovementArgs) -> anyhow::Result<()>;

	/// Fetch a VTXO by id in the database
	fn get_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>>;
	/// Fetch all VTXO's that are in a given state
	fn get_vtxos_by_state(&self, state: &[VtxoState]) -> anyhow::Result<Vec<Vtxo>>;
	/// Remove a VTXO from the database
	fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>>;
	/// Check whether a VTXO has been spent already or not
	fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool>;

	/// Store a newly revealed index
	fn store_vtxo_key(&self, keychain: KeychainKind, index: u32, public_key: PublicKey) -> anyhow::Result<()>;
	/// Get last revealed index
	fn get_last_vtxo_key_index(&self, keychain: KeychainKind) -> anyhow::Result<Option<u32>>;
	/// Get index of vtxo key
	fn get_vtxo_key(&self, vtxo: &Vtxo) -> anyhow::Result<(KeychainKind, u32)>;
	/// Checks if provided public key exists in the database,
	/// meaning that it is owned by the wallet
	fn check_vtxo_key_exists(&self, public_key: &PublicKey) -> anyhow::Result<bool>;

	/// Store an offchain onboard
	fn store_offchain_onboard(&self, payment_hash: &[u8; 32], preimage: &[u8; 32], payment: OffchainPayment) -> anyhow::Result<()>;
	/// Fetch an offchain onboard by payment hash
	fn fetch_offchain_onboard_by_payment_hash(&self, payment_hash: &[u8; 32]) -> anyhow::Result<Option<OffchainOnboard>>;

	/// Store the ongoing exit process.
	fn store_exit(&self, exit: &ExitIndex) -> anyhow::Result<()>;
	/// Fetch an ongoing exit process.
	fn fetch_exit(&self) -> anyhow::Result<Option<ExitIndex>>;

	fn get_last_ark_sync_height(&self) -> anyhow::Result<BlockHeight>;
	fn store_last_ark_sync_height(&self, height: BlockHeight) -> anyhow::Result<()>;

	fn update_vtxo_state_checked(&self, vtxo_id: VtxoId, new_state: VtxoState, allowed_old_states: &[VtxoState]) -> anyhow::Result<()>;

	/// Fetch all currently spendable VTXOs in the database
	fn get_all_spendable_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		self.get_vtxos_by_state(&[VtxoState::Spendable])
	}
}
