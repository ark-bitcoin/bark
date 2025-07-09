pub mod sqlite;

use bdk_wallet::ChangeSet;
use bitcoin::{Transaction, Txid};
use bitcoin::secp256k1::PublicKey;

use ark::{Vtxo, VtxoId};
use bitcoin_ext::{BlockHeight, BlockRef};
use lightning_invoice::Bolt11Invoice;

use crate::{
	Config, KeychainKind, Movement, MovementArgs, Pagination,
	WalletProperties,
};
use crate::exit::vtxo::ExitEntry;
use crate::vtxo_state::{VtxoState, VtxoStateKind, WalletVtxo};

#[derive(Clone, Serialize, Deserialize)]
pub enum OffchainPayment {
	Lightning(Bolt11Invoice),
}

pub struct OffchainBoard {
	pub payment_hash: [u8; 32],
	pub payment_preimage: [u8; 32],
	pub payment: OffchainPayment,
}

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

	/// Register a movement of VTXOs.
	///
	/// This call will also:
	/// - create new VTXOs in `receives` in the database
	/// - mark VTXOs in `spends` as spent
	fn register_movement(&self, movement: MovementArgs) -> anyhow::Result<()>;

	/// Fetch a VTXO by id in the database
	fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>>;
	/// Fetch all VTXO's that are in a given state
	fn get_vtxos_by_state(&self, state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>>;
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

	/// Store an offchain board
	fn store_offchain_board(&self, payment_hash: &[u8; 32], preimage: &[u8; 32], payment: OffchainPayment) -> anyhow::Result<()>;
	/// Fetch an offchain board by payment hash
	fn fetch_offchain_board_by_payment_hash(&self, payment_hash: &[u8; 32]) -> anyhow::Result<Option<OffchainBoard>>;

	/// Store the VTXOs currently being exited
	fn store_exit_vtxo_entry(&self, exit: &ExitEntry) -> anyhow::Result<()>;
	/// Removes the given VTXO from the database
	fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()>;
	/// Gets the VTXOs currently being exited
	fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<ExitEntry>>;
	/// Stores the given child transaction for future retrieval
	fn store_exit_child_tx(
		&self,
		exit_txid: Txid,
		child_tx: &Transaction,
		block: Option<BlockRef>,
	) -> anyhow::Result<()>;
	/// Get any stored child transaction for the given exit transaction
	fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, Option<BlockRef>)>>;

	fn get_last_ark_sync_height(&self) -> anyhow::Result<BlockHeight>;
	fn store_last_ark_sync_height(&self, height: BlockHeight) -> anyhow::Result<()>;

	fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo>;

	/// Fetch all currently spendable VTXOs in the database
	fn get_all_spendable_vtxos(&self) -> anyhow::Result<Vec<Vtxo>> {
		Ok(self.get_vtxos_by_state(&[VtxoStateKind::Spendable])?.into_iter().map(|vtxo| vtxo.vtxo).collect())
	}
}

