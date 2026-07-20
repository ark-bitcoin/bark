//! Persistence abstractions for Bark wallets.
//!
//! This module defines the [BarkPersister] trait and related data models used by the
//! wallet to store and retrieve state. Implementors can provide their own storage backends
//! (e.g., SQLite, PostgreSQL, in-memory, mobile key/value stores) by implementing the
//! [BarkPersister] trait.
//!
//! Design goals
//! - Clear separation between wallet logic and storage.
//! - Transactional semantics where appropriate (round state transitions, movement recording).
//! - Portability across different platforms and environments.
//!
//! Typical usage
//! - Applications construct a concrete persister (for example, a SQLite-backed client) and
//!   pass it to the [crate::Wallet]. The [crate::Wallet] only depends on this trait for reads/writes.
//! - Custom wallet implementations can reuse this trait to remain compatible with Bark
//!   storage expectations without depending on a specific database.
//! - A default rusqlite implementation is provided by [sqlite::SqliteClient].

pub mod adaptor;
pub mod models;
#[cfg(feature = "sqlite")]
pub mod sqlite;
#[cfg(test)]
pub(crate) mod test_suite;


use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::bip32::Fingerprint;
use bitcoin::{Amount, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use chrono::DateTime;
use lightning_invoice::Bolt11Invoice;
#[cfg(feature = "onchain-bdk")]
use bdk_wallet::ChangeSet;

use ark::{Vtxo, VtxoId};
use ark::lightning::{PaymentHash, Preimage};
use ark::vtxo::Full;

use crate::WalletProperties;
use crate::actions::{WalletActionCheckpoint, WalletActionId};
use crate::exit::{ExitTxOrigin, ExitStateKind};
use crate::persist::models::{
	PaidInvoice, RoundStateId, SettledLightningReceive, StoredExit, StoredRoundState, Unlocked,
};
use crate::movement::{Movement, MovementId, MovementStatus, MovementSubsystem, PaymentMethod};
use crate::movement::update::MovementUpdate;
use crate::round::RoundState;
use crate::vtxo::{VtxoState, VtxoStateKind, WalletVtxo};

/// Storage interface for Bark wallets.
///
/// Implement this trait to plug a custom persistence backend. The wallet uses it to:
/// - Initialize and read wallet properties and configuration.
/// - Record movements (spends/receives), recipients, and enforce [Vtxo] state transitions.
/// - Manage round lifecycles (attempts, pending confirmation, confirmations/cancellations).
/// - Persist ephemeral protocol artifacts (e.g., secret nonces) transactionally.
/// - Track Lightning receives and preimage revelation.
/// - Track exit-related data and associated child transactions.
/// - Persist the last synchronized Ark block height.
///
/// Feature integration:
/// - With the `onchain-bdk` feature, methods are provided to initialize and persist a BDK
///   wallet ChangeSet in the same storage.
///
/// Notes for implementors:
/// - Ensure that operations that change multiple records (e.g., registering a movement,
///   storing round state transitions) are executed transactionally.
/// - Enforce state integrity by verifying allowed_old_states before updating a [Vtxo] state.
/// - If your backend is not thread-safe, prefer a short-lived connection per call or use
///   an internal pool with checked-out connections per operation.
/// - Return precise errors so callers can surface actionable diagnostics.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait BarkPersister: Send + Sync + 'static {
	/// Check if the wallet is initialized.
	///
	/// Returns:
	/// - `Ok(true)` if the wallet is initialized.
	/// - `Ok(false)` if the wallet is not initialized.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn is_initialized(&self) -> anyhow::Result<bool> {
		Ok(self.read_properties().await?.is_some())
	}

	/// Initialize a wallet in storage with the provided properties.
	///
	/// Call exactly once per wallet database. Subsequent calls should fail to prevent
	/// accidental re-initialization.
	///
	/// Parameters:
	/// - properties: WalletProperties to persist (e.g., network, descriptors, metadata).
	///
	/// Returns:
	/// - `Ok(())` on success.
	///
	/// Errors:
	/// - Returns an error if the wallet is already initialized or if persistence fails.
	async fn init_wallet(&self, properties: &WalletProperties) -> anyhow::Result<()>;

	/// Initialize the onchain BDK wallet and return any previously stored ChangeSet.
	///
	/// Must be called before storing any new BDK changesets to bootstrap the BDK state.
	///
	/// Feature: only available with `onchain-bdk`.
	///
	/// Returns:
	/// - `Ok(ChangeSet)` containing the previously persisted BDK state (possibly empty).
	///
	/// Errors:
	/// - Returns an error if the BDK state cannot be created or loaded.
	#[cfg(feature = "onchain-bdk")]
	async fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet>;

	/// Persist an incremental BDK ChangeSet.
	///
	/// The changeset should be applied atomically. Callers typically obtain the changeset
	/// from a BDK wallet instance after mutating wallet state (e.g., sync).
	///
	/// Feature: only available with `onchain-bdk`.
	///
	/// Parameters:
	/// - changeset: The BDK ChangeSet to persist.
	///
	/// Errors:
	/// - Returns an error if the changeset cannot be written.
	#[cfg(feature = "onchain-bdk")]
	async fn store_bdk_wallet_changeset(&self, changeset: &ChangeSet) -> anyhow::Result<()>;

	/// Read wallet properties from storage.
	///
	/// Returns:
	/// - `Ok(Some(WalletProperties))` if the wallet has been initialized.
	/// - `Ok(None)` if no wallet exists yet.
	///
	/// Errors:
	/// - Returns an error on I/O or deserialization failures.
	async fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>>;

	/// Set the server public key in wallet properties.
	///
	/// This is used to store the server pubkey for existing wallets that were
	/// created before server pubkey tracking was added. Once set, the wallet
	/// will verify the server pubkey on every connection.
	///
	/// Parameters:
	/// - server_pubkey: The server's public key to store.
	///
	/// Errors:
	/// - Returns an error if the update fails.
	async fn set_server_pubkey(&self, server_pubkey: PublicKey) -> anyhow::Result<()>;

	/// Set the server's mailbox public key in wallet properties.
	///
	/// This is used to store the server mailbox pubkey for existing wallets that were
	/// created before mailbox pubkey tracking was added. Once set, Ark addresses
	/// can be generated offline without a live server connection.
	///
	/// Parameters:
	/// - server_mailbox_pubkey: The server's mailbox public key to store.
	///
	/// Errors:
	/// - Returns an error if the update fails.
	async fn set_server_mailbox_pubkey(&self, server_mailbox_pubkey: PublicKey) -> anyhow::Result<()>;

	/// Creates a new movement in the given state, ready to be updated.
	///
	/// Parameters:
	/// - status: The desired status for the new movement.
	/// - subsystem: The subsystem that created the movement.
	/// - time: The time the movement should be marked as created.
	///
	/// Returns:
	/// - `Ok(MovementId)` of the newly created movement.
	///
	/// Errors:
	/// - Returns an error if the movement is unable to be created.
	async fn create_new_movement(&self,
		status: MovementStatus,
		subsystem: &MovementSubsystem,
		time: DateTime<chrono::Local>,
		action_id: Option<&str>,
	) -> anyhow::Result<MovementId>;

	/// Atomically look up the movement owned by `action_id`, or create it and
	/// apply `update` as its initial state, in a single transaction.
	///
	/// A movement created this way is indexed by `action_id`, so a re-driven
	/// action step (crash recovery, an early wake, the reentrancy double-drive)
	/// reuses its existing, already-initialized movement. Doing the lookup,
	/// insert and initial update atomically means a re-drive never observes a
	/// half-written movement and never inserts a duplicate.
	///
	/// Returns the movement id and whether it was newly created, so the caller
	/// can dispatch the `created` notification exactly once.
	async fn get_or_create_movement_for_action(
		&self,
		subsystem: &MovementSubsystem,
		time: DateTime<chrono::Local>,
		action_id: &str,
		update: MovementUpdate,
	) -> anyhow::Result<(MovementId, bool)>;

	/// Persists the given movement state.
	///
	/// Parameters:
	/// - movement: The movement and its associated data to be persisted.
	///
	/// Errors:
	/// - Returns an error if updating the movement fails for any reason.
	async fn update_movement(&self, movement: &Movement) -> anyhow::Result<()>;

	/// Gets the movement with the given [MovementId].
	///
	/// Parameters:
	/// - movement_id: The ID of the movement to retrieve.
	///
	/// Returns:
	/// - `Ok(Movement)` if the movement exists.
	///
	/// Errors:
	/// - If the movement does not exist.
	/// - If retrieving the movement fails.
	async fn get_movement_by_id(&self, movement_id: MovementId) -> anyhow::Result<Movement>;

	/// Gets every stored movement.
	///
	/// Returns:
	/// - `Ok(Vec<Movement>)` containing all movements, empty if none exist.
	///
	/// Errors:
	/// - If retrieving the movements fails.
	async fn get_all_movements(&self) -> anyhow::Result<Vec<Movement>>;

	/// Get all movements for a given payment method
	///
	/// Parameters:
	/// - `payment_method`: The [PaymentMethod] to look up.
	///
	/// Returns:
	/// - `Ok(movements)` containing all relevant movements, empty if none exist.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_movements_by_payment_method(
		&self,
		payment_method: &PaymentMethod,
	) -> anyhow::Result<Vec<Movement>>;

	/// Store a new ongoing round state
	///
	/// The holder should ensure the input VTXOs are available and locked.
	///
	/// Parameters:
	/// - `round_state`: the state to store
	///
	/// Returns:
	/// - `RoundStateId`: the storaged ID of the new state
	///
	/// Errors:
	/// - returns an error of the new round state could not be stored
	async fn store_round_state(&self, round_state: &RoundState) -> anyhow::Result<RoundStateId>;

	/// Update an existing stored pending round state
	///
	/// Parameters:
	/// - `round_state`: the round state to update
	///
	/// Errors:
	/// - returns an error of the existing round state could not be found or updated
	async fn update_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()>;

	/// Remove a pending round state from the db
	///
	/// Parameters:
	/// - `round_state`: the round state to remove
	///
	/// Errors:
	/// - returns an error of the existing round state could not be found or removed
	async fn remove_round_state(&self, round_state: &StoredRoundState) -> anyhow::Result<()>;

	/// Load a single round state by its id
	///
	/// Returns:
	/// - `Option<StoredRoundState>`: the stored round state if found, `None` otherwise
	///
	/// Errors:
	/// - returns an error of the states could not be succesfully retrieved
	async fn get_round_state_by_id(&self, id: RoundStateId) -> anyhow::Result<Option<StoredRoundState<Unlocked>>>;

	/// Load all pending round states from the db
	///
	/// Returns:
	/// - `Vec<RoundStateId>`: unordered vector with all stored round state ids
	///
	/// Errors:
	/// - returns an error of the ids could not be succesfully retrieved
	async fn get_pending_round_state_ids(&self) -> anyhow::Result<Vec<RoundStateId>>;

	/// Stores VTXOs with their initial state.
	///
	/// This operation is idempotent: if a VTXO already exists (same `id`), the
	/// implementation should succeed without modifying the existing VTXO or its
	/// state. This allows safe retries during crash recovery scenarios.
	///
	/// # Parameters
	/// - `vtxos`: Slice of VTXO and state pairs to store.
	///
	/// # Behavior
	/// - For each VTXO that does not exist: inserts the VTXO and its initial state.
	/// - For each VTXO that already exists: no-op for that VTXO.
	///
	/// # Errors
	/// - Returns an error if the storage operation fails.
	async fn store_vtxos(
		&self,
		vtxos: &[(&Vtxo<Full>, &VtxoState)],
	) -> anyhow::Result<()>;

	/// Fetch a wallet [Vtxo] with its current state by ID.
	///
	/// Parameters:
	/// - id: [VtxoId] to look up.
	///
	/// Returns:
	/// - `Ok(Some(WalletVtxo))` if found,
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the lookup fails.
	async fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>>;

	/// Fetch multiple wallet VTXOs by id, preserving the order of the
	/// input slice.
	///
	/// Parameters:
	/// - ids: [VtxoId]s to look up.
	///
	/// Returns:
	/// - `Ok(Vec<WalletVtxo>)` with one entry per input id, in order.
	///
	/// Errors:
	/// - Returns an error if any id is missing or the lookup fails.
	async fn get_wallet_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<WalletVtxo>>;

	/// Fetch all wallet VTXOs in the database.
	///
	/// Returns:
	/// - `Ok(Vec<WalletVtxo>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>>;

	/// Fetch all wallet VTXOs whose state matches any of the provided kinds.
	///
	/// Parameters:
	/// - state: Slice of `VtxoStateKind` filters.
	///
	/// Returns:
	/// - `Ok(Vec<WalletVtxo>)` possibly empty, sorted by expiry height
	///   ascending, then by amount descending. Callers rely on this order
	///   to prioritize VTXOs that expire sooner and are larger.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_vtxos_by_state(&self, state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>>;

	/// Fetch a single VTXO in full form (including the unilateral exit chain).
	///
	/// Listing/balance/selection paths return [WalletVtxo] (which holds
	/// [Vtxo<ark::vtxo::Bare>]) to keep memory bounded. Operations that
	/// genuinely need the genesis chain — unilateral exit, server
	/// registration, arkoor send, offboard — should call this method
	/// (or [BarkPersister::get_full_vtxos] for batches) on demand.
	async fn get_full_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>>;

	/// Hydrate a batch of VTXOs into their full form, preserving the order
	/// of the input slice. Returns an error if any id is missing — callers
	/// reach this from a selection step against the wallet's listings, so a
	/// missing row indicates the wallet's state is inconsistent with the
	/// caller's view.
	async fn get_full_vtxos(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<Vtxo<Full>>>;

	/// Remove a [Vtxo] by ID.
	///
	/// Parameters:
	/// - id: `VtxoId` to remove.
	///
	/// Returns:
	/// - `Ok(Some(Vtxo))` with the removed [Vtxo] data if it existed,
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the delete operation fails.
	async fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo<Full>>>;

	/// Check whether a [Vtxo] is already marked spent.
	///
	/// Parameters:
	/// - id: VtxoId to check.
	///
	/// Returns:
	/// - `Ok(true)` if spent,
	/// - `Ok(false)` if not found or not spent.
	///
	/// Errors:
	/// - Returns an error if the lookup fails.
	async fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool>;

	/// Store a newly derived/assigned [Vtxo] public key index mapping.
	///
	/// Parameters:
	/// - index: Derivation index.
	/// - public_key: PublicKey at that index.
	///
	/// Errors:
	/// - Returns an error if the mapping cannot be stored.
	async fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()>;

	/// Get the last revealed/used [Vtxo] key index.
	///
	/// Returns:
	/// - `Ok(Some(u32))` if a key was stored
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>>;

	/// Retrieves the derivation index of the provided [PublicKey] from the database
	///
	/// Returns:
	/// - `Ok(Some(u32))` if the key was stored.
	/// - `Ok(None)` if the key was not stored.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_public_key_idx(&self, public_key: &PublicKey) -> anyhow::Result<Option<u32>>;

	/// Retrieves the mailbox checkpoint from the database
	///
	/// Returns:
	/// - `Ok(u64)` the stored checkpoint.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_mailbox_checkpoint(&self) -> anyhow::Result<u64>;

	/// Update the mailbox checkpoint to the new checkpoint
	///
	/// Returns:
	///
	///
	/// Errors:
	/// - Returns error when the query fails
	/// - Returns error when the provided checkpoint is smaller than the existing checkpoint
	async fn store_mailbox_checkpoint(&self, checkpoint: u64) -> anyhow::Result<()>;

	/// Persist or overwrite a wallet action checkpoint.
	///
	/// Parameters:
	/// - id: stable action identifier (e.g. payment hash hex for a lightning send).
	/// - checkpoint: the payload to persist; replaces any existing row with the same id.
	///
	/// Errors:
	/// - Returns an error if the write fails.
	async fn upsert_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
		checkpoint: &WalletActionCheckpoint,
	) -> anyhow::Result<()>;

	/// Fetch a wallet action checkpoint by id.
	///
	/// Returns:
	/// - `Ok(Some(_))` if a row exists, `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the lookup or deserialization fails.
	async fn get_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<Option<WalletActionCheckpoint>>;

	/// Fetch every persisted wallet action checkpoint, oldest first.
	///
	/// Used by the periodic sync to find work to re-drive.
	async fn get_all_wallet_action_checkpoints(
		&self,
	) -> anyhow::Result<Vec<WalletActionCheckpoint>>;

	/// Remove a wallet action checkpoint by id. No-op if absent.
	async fn remove_wallet_action_checkpoint(
		&self,
		id: &WalletActionId,
	) -> anyhow::Result<()>;

	/// Record a settled outgoing lightning send.
	///
	/// Idempotent: a subsequent call with the same payment_hash is a
	/// no-op (the existing row wins). This makes retry across a crash
	/// safe even without a multi-row transaction.
	async fn record_paid_invoice(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
	) -> anyhow::Result<()>;

	/// Look up an existing paid-invoice record by payment hash.
	async fn get_paid_invoice(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<PaidInvoice>>;

	/// Record a settled incoming lightning receive, ignore if already exists.
	async fn record_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
		invoice: &Bolt11Invoice,
		amount: Amount,
	) -> anyhow::Result<()>;

	/// Look up a settled lightning receive record by payment hash.
	async fn get_settled_lightning_receive(
		&self,
		payment_hash: PaymentHash,
	) -> anyhow::Result<Option<SettledLightningReceive>>;

	/// Store an entry indicating a [Vtxo] is being exited.
	///
	/// Parameters:
	/// - exit: StoredExit describing the exit operation.
	///
	/// Errors:
	/// - Returns an error if the entry cannot be stored.
	async fn store_exit_vtxo_entry(&self, exit: &StoredExit) -> anyhow::Result<()>;

	/// Remove an exit entry for a given [Vtxo] ID.
	///
	/// Parameters:
	/// - id: VtxoId to remove from exit tracking.
	///
	/// Errors:
	/// - Returns an error if the removal fails.
	async fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()>;

	/// List all VTXOs currently tracked as being exited.
	///
	/// Returns:
	/// - `Ok(Vec<StoredExit>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>>;

	/// List exit entries whose current state matches one of the given [ExitStateKind]s.
	///
	/// Errors:
	/// - Returns an error if the underlying query fails.
	async fn get_exit_vtxo_entries_with_states(
		&self,
		states: &[ExitStateKind],
	) -> anyhow::Result<Vec<StoredExit>>;

	/// Fetch the exit entry for a single [Vtxo] ID, if any.
	///
	/// Returns:
	/// - `Ok(Some(StoredExit))` if the VTXO has an exit entry, `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	async fn get_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<Option<StoredExit>>;

	/// Store a child transaction related to an exit transaction.
	///
	/// Parameters:
	/// - exit_txid: The parent exit transaction ID.
	/// - child_tx: The child bitcoin Transaction to store.
	/// - origin: Metadata describing where the child came from (ExitTxOrigin).
	///
	/// Errors:
	/// - Returns an error if the transaction cannot be stored.
	async fn store_exit_child_tx(
		&self,
		exit_txid: Txid,
		child_tx: &Transaction,
		origin: ExitTxOrigin,
	) -> anyhow::Result<()>;

	/// Retrieve a stored child transaction for a given exit transaction ID.
	///
	/// Parameters:
	/// - exit_txid: The parent exit transaction ID.
	///
	/// Returns:
	/// - `Ok(Some((Transaction, ExitTxOrigin)))` if found,
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the lookup fails.
	async fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>>;

	/// Updates the state of the VTXO corresponding to the given [VtxoId], provided that their
	/// current state is one of the given `allowed_states`.
	///
	/// # Parameters
	/// - `vtxo_id`: The ID of the [Vtxo] to update.
	/// - `state`: The new state to be set for the specified [Vtxo].
	/// - `allowed_states`: An iterable collection of allowed states ([VtxoStateKind]) that the
	///   [Vtxo] must currently be in for their state to be updated to the new `state`.
	///
	/// # Returns
	/// - `Ok(WalletVtxo)` if the state update is successful.
	/// - `Err(anyhow::Error)` if the VTXO fails to meet the required conditions,
	///    or if another error occurs during the operation.
	///
	/// # Errors
	/// - Returns an error if the current state is not within the `allowed_states`.
	/// - Returns an error for any other issues encountered during the operation.
	async fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo>;

	/// Transition multiple VTXOs to `new_state` atomically: either every
	/// vtxo's state changes or none does. A failure must not affect any
	/// vtxo.
	async fn update_vtxo_states_checked(
		&self,
		vtxo_ids: &[VtxoId],
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<()>;
}

/// Return the recommended [`BarkPersister`] backend for the current
/// build target.
///
/// UNIX and Windows platforms require datadir, wasm32 requires fingerprint.
#[allow(unreachable_code)]
pub async fn platform_default(
	datadir: Option<impl Into<PathBuf>>,
	wallet_fingerprint: Option<Fingerprint>,
) -> anyhow::Result<Arc<dyn BarkPersister>> {
	#[cfg(all(target_arch = "wasm32", feature = "indexed-db"))]
	{
		let _ = datadir;
		let fingerprint = wallet_fingerprint
			.context("wallet fingerprint argument is required for this platform")?;
		let client = crate::persist::adaptor::indexed_db::IndexedDbClient::open(
			&fingerprint.to_string(),
		).await?;
		return Ok(Arc::new(self::adaptor::StorageAdaptorWrapper::new(client)))
	}

	#[cfg(all(any(unix, windows), not(target_arch = "wasm32"), feature = "sqlite"))]
	{
		let _ = wallet_fingerprint;
		let datadir = datadir.context("datadir argument is required for this platform")?;
		let dbfile = {
			let mut buf = datadir.into();
			buf.push(crate::persist::sqlite::DEFAULT_DB_FILE);
			buf
		};
		return Ok(Arc::new(crate::persist::sqlite::SqliteClient::open(dbfile)?));
	}

	bail!("persist::platform_default: no default backend for this target");
}
