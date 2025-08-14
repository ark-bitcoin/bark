pub mod sqlite;

#[cfg(feature = "onchain_bdk")]
use bdk_wallet::ChangeSet;

use bitcoin::{Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;

use ark::{Vtxo, VtxoId};
use ark::lightning::{PaymentHash, Preimage};
use bitcoin_ext::BlockHeight;
use json::exit::states::ExitTxOrigin;

use crate::{
	Config, Movement, MovementArgs, Pagination,
	WalletProperties,
};
use crate::exit::vtxo::ExitEntry;
use crate::vtxo_state::{VtxoState, VtxoStateKind, WalletVtxo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightningReceive {
	pub payment_hash: PaymentHash,
	pub payment_preimage: Preimage,
	pub invoice: Bolt11Invoice,
	pub preimage_revealed_at: Option<u64>,
}

pub trait BarkPersister: Send + Sync + 'static {
	/// Initialise wallet in the database
	///
	/// Will fail after first call
	fn init_wallet(&self, config: &Config, properties: &WalletProperties) -> anyhow::Result<()>;

	/// Initialize the BDK wallet and load the full existing ChangeSet.
	///
	/// This function must be called before any new changeset is stored.

	#[cfg(feature = "onchain_bdk")]
	fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet>;
	/// Store the incremental changeset of the BDK wallet.

	#[cfg(feature = "onchain_bdk")]
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
	fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()>;
	/// Get last revealed index
	fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>>;
	/// Get index of vtxo key
	fn get_vtxo_key(&self, vtxo: &Vtxo) -> anyhow::Result<u32>;
	/// Checks if provided public key exists in the database,
	/// meaning that it is owned by the wallet
	fn check_vtxo_key_exists(&self, public_key: &PublicKey) -> anyhow::Result<bool>;

	/// Store a lightning receive
	fn store_lightning_receive(&self, payment_hash: PaymentHash, preimage: Preimage, invoice: &Bolt11Invoice) -> anyhow::Result<()>;
	/// Returns a paginated list of lightning receives
	fn get_paginated_lightning_receives(&self, pagination: Pagination) -> anyhow::Result<Vec<LightningReceive>>;
	/// Set preimage disclosed
	fn set_preimage_revealed(&self, payment_hash: PaymentHash) -> anyhow::Result<()>;
	/// Fetch a lightning receive by payment hash
	fn fetch_lightning_receive_by_payment_hash(&self, payment_hash: PaymentHash) -> anyhow::Result<Option<LightningReceive>>;

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
		origin: ExitTxOrigin,
	) -> anyhow::Result<()>;
	/// Get any stored child transaction for the given exit transaction.
	fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>>;

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

