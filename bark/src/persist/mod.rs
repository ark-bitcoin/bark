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

pub mod models;
pub mod sqlite;

#[cfg(feature = "onchain_bdk")]
use bdk_wallet::ChangeSet;

use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::musig::SecretNonce;
use ark::rounds::{RoundId, RoundSeq};
use bitcoin::{Amount, Transaction, Txid};
use bitcoin::secp256k1::PublicKey;
use lightning_invoice::Bolt11Invoice;

use ark::{Vtxo, VtxoId};
use json::exit::states::ExitTxOrigin;

use crate::{Movement, MovementArgs, WalletProperties};
use crate::persist::models::{PendingLightningSend, LightningReceive, StoredExit, StoredVtxoRequest};
use crate::round::{AttemptStartedState, PendingConfirmationState, RoundParticipation, RoundState};
use crate::vtxo_state::{VtxoState, VtxoStateKind, WalletVtxo};

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
/// - With the `onchain_bdk` feature, methods are provided to initialize and persist a BDK
///   wallet ChangeSet in the same storage.
///
/// Notes for implementors:
/// - Ensure that operations that change multiple records (e.g., registering a movement,
///   storing round state transitions) are executed transactionally.
/// - Enforce state integrity by verifying allowed_old_states before updating a [Vtxo] state.
/// - If your backend is not thread-safe, prefer a short-lived connection per call or use
///   an internal pool with checked-out connections per operation.
/// - Return precise errors so callers can surface actionable diagnostics.
pub trait BarkPersister: Send + Sync + 'static {
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
	fn init_wallet(&self, properties: &WalletProperties) -> anyhow::Result<()>;

	/// Initialize the onchain BDK wallet and return any previously stored ChangeSet.
	///
	/// Must be called before storing any new BDK changesets to bootstrap the BDK state.
	///
	/// Feature: only available with `onchain_bdk`.
	///
	/// Returns:
	/// - `Ok(ChangeSet)` containing the previously persisted BDK state (possibly empty).
	///
	/// Errors:
	/// - Returns an error if the BDK state cannot be created or loaded.
	#[cfg(feature = "onchain_bdk")]
	fn initialize_bdk_wallet(&self) -> anyhow::Result<ChangeSet>;

	/// Persist an incremental BDK ChangeSet.
	///
	/// The changeset should be applied atomically. Callers typically obtain the changeset
	/// from a BDK wallet instance after mutating wallet state (e.g., sync).
	///
	/// Feature: only available with `onchain_bdk`.
	///
	/// Parameters:
	/// - changeset: The BDK ChangeSet to persist.
	///
	/// Errors:
	/// - Returns an error if the changeset cannot be written.
	#[cfg(feature = "onchain_bdk")]
	fn store_bdk_wallet_changeset(&self, changeset: &ChangeSet) -> anyhow::Result<()>;

	/// Read wallet properties from storage.
	///
	/// Returns:
	/// - `Ok(Some(WalletProperties))` if the wallet has been initialized.
	/// - `Ok(None)` if no wallet exists yet.
	///
	/// Errors:
	/// - Returns an error on I/O or deserialization failures.
	fn read_properties(&self) -> anyhow::Result<Option<WalletProperties>>;

	/// Check whether a recipient identifier already exists.
	///
	/// Useful to avoid storing duplicate recipients for the same logical payee or duplicated
	/// lightning invoice payments (unsafe)
	///
	/// Parameters:
	/// - recipient: A recipient identifier (e.g., invoice).
	///
	/// Returns:
	/// - `Ok(true)` if the recipient exists,
	/// - `Ok(false)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the lookup fails.
	fn check_recipient_exists(&self, recipient: &str) -> anyhow::Result<bool>;

	/// Return a list of movements, see [Movement].
	///
	/// Returns:
	/// - `Ok(Vec<Movement>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_movements(&self) -> anyhow::Result<Vec<Movement>>;

	/// Register a movement of VTXOs atomically.
	///
	/// Side effects:
	/// - Creates new VTXOs in `receives`.
	/// - Marks VTXOs in `spends` as spent (with state checks).
	/// - Optionally stores recipients and fees.
	///
	/// Parameters:
	/// - movement: [MovementArgs] including spends, receives, recipients and fees.
	///
	/// Errors:
	/// - Returns an error if any part of the operation fails; no partial state should be
	///   committed in that case.
	fn register_movement(&self, movement: MovementArgs) -> anyhow::Result<()>;

	/// Store a pending board.
	///
	/// Parameters:
	/// - vtxo: The [Vtxo] to store.
	/// - funding_txid: The funding transaction ID.
	///
	/// Errors:
	/// - Returns an error if the board cannot be stored.
	fn store_pending_board(&self, vtxo: &Vtxo, funding_tx: &Transaction) -> anyhow::Result<()>;

	/// Remove a pending board.
	///
	/// Parameters:
	/// - vtxo_id: The [VtxoId] to remove.
	///
	/// Errors:
	/// - Returns an error if the board cannot be removed.
	fn remove_pending_board(&self, vtxo_id: &VtxoId) -> anyhow::Result<()>;

	/// Get all pending boards.
	///
	/// Returns:
	/// - `Ok(Vec<VtxoId>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_all_pending_boards(&self) -> anyhow::Result<Vec<VtxoId>>;

	/// Create a new round attempt with the initial [AttemptStartedState].
	///
	/// Parameters:
	/// - round_seq: Monotonic round sequence number.
	/// - attempt_seq: Attempt index within the round sequence.
	/// - round_participation: Participation details for the wallet.
	///
	/// Returns:
	/// - `Ok(AttemptStartedState)` persisted.
	///
	/// Errors:
	/// - Returns an error if the round attempt cannot be created (e.g., conflicts).
	fn store_new_round_attempt(
		&self,
	    round_seq: RoundSeq,
		attempt_seq: usize,
		round_participation: RoundParticipation,
	) -> anyhow::Result<AttemptStartedState>;

	/// Transition a round to [PendingConfirmationState], persisting round tx and [Vtxo] effects.
	///
	/// Parameters:
	/// - round_txid: Round transaction identifier.
	/// - round_tx: Full round [Transaction].
	/// - reqs: [StoredVtxoRequest] entries associated to the round.
	/// - vtxos: VTXOs produced or affected by the round.
	///
	/// Returns:
	/// - `Ok(PendingConfirmationState)` persisted.
	///
	/// Errors:
	/// - Returns an error if any element cannot be stored atomically.
	fn store_pending_confirmation_round(
		&self,
		round_txid: RoundId,
		round_tx: Transaction,
		reqs: Vec<StoredVtxoRequest>,
		vtxos: Vec<Vtxo>,
	) -> anyhow::Result<PendingConfirmationState>;

	/// Store a round state update, validating the previous state.
	///
	/// Parameters:
	/// - round_state: The new [RoundState] to persist.
	/// - prev_state: The expected current [RoundState]; used to prevent invalid transitions.
	///
	/// Returns:
	/// - `Ok(RoundState)` persisted state.
	///
	/// Errors:
	/// - Returns an error if the transition is invalid or writing fails.
	fn store_round_state(&self, round_state: RoundState, prev_state: RoundState) -> anyhow::Result<RoundState>;

	/// Store secret nonces associated with a specific round attempt.
	///
	/// The nonces are ephemeral and typically consumed once. Store atomically.
	///
	/// Parameters:
	/// - round_attempt_id: Identifier of the round attempt.
	/// - secret_nonces: Nested collection of SecretNonce sets (e.g., per input/output). These
	///   nonces should only ever be accessed using `take_secret_nonces` to avoid the risk of reuse.
	///
	/// Errors:
	/// - Returns an error if the nonces cannot be persisted.
	fn store_secret_nonces(&self, round_attempt_id: i64, secret_nonces: Vec<Vec<SecretNonce>>) -> anyhow::Result<()>;

	/// Take and remove secret nonces for a round attempt (consume-once semantics).
	///
	/// Parameters:
	/// - round_attempt_id: Identifier of the round attempt.
	///
	/// Returns:
	/// - `Ok(Some(nonches))` if found
	/// - `Ok(None)` if none exist.
	///
	/// Errors:
	/// - Returns an error if retrieval or deletion fails.
	fn take_secret_nonces(&self, round_attempt_id: i64) -> anyhow::Result<Option<Vec<Vec<SecretNonce>>>>;

	/// Fetch a round by its internal attempt ID.
	///
	/// Parameters:
	/// - round_attempt_id: Attempt identifier.
	///
	/// Returns:
	/// - `Ok(Some(RoundState))` if found,
	/// - `Ok(None)` if not present.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_round_attempt_by_id(&self, round_attempt_id: i64) -> anyhow::Result<Option<RoundState>>;

	/// Fetch a round by its round transaction ID.
	///
	/// Parameters:
	/// - round_id: Round transaction ID.
	///
	/// Returns:
	/// - `Ok(Some(RoundState))` if found,
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_round_attempt_by_round_txid(&self, round_id: RoundId) -> anyhow::Result<Option<RoundState>>;

	/// List all rounds that are pending (e.g., awaiting confirmation or resolution).
	///
	/// Returns:
	/// - `Ok(Vec<RoundState>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn list_pending_rounds(&self) -> anyhow::Result<Vec<RoundState>>;

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
	fn get_wallet_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<WalletVtxo>>;

	/// Fetch all wallet VTXOs in the database.
	///
	/// Returns:
	/// - `Ok(Vec<WalletVtxo>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>>;

	/// Fetch all wallet VTXOs whose state matches any of the provided kinds.
	///
	/// Parameters:
	/// - state: Slice of `VtxoStateKind` filters.
	///
	/// Returns:
	/// - `Ok(Vec<WalletVtxo>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_vtxos_by_state(&self, state: &[VtxoStateKind]) -> anyhow::Result<Vec<WalletVtxo>>;

	/// Fetch all VTXOs currently engaged in an active round.
	///
	/// Returns:
	/// - `Ok(Vec<Vtxo>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_in_round_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>>;

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
	fn remove_vtxo(&self, id: VtxoId) -> anyhow::Result<Option<Vtxo>>;

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
	fn has_spent_vtxo(&self, id: VtxoId) -> anyhow::Result<bool>;

	/// Store a newly derived/assigned [Vtxo] public key index mapping.
	///
	/// Parameters:
	/// - index: Derivation index.
	/// - public_key: PublicKey at that index.
	///
	/// Errors:
	/// - Returns an error if the mapping cannot be stored.
	fn store_vtxo_key(&self, index: u32, public_key: PublicKey) -> anyhow::Result<()>;

	/// Get the last revealed/used [Vtxo] key index.
	///
	/// Returns:
	/// - `Ok(Some(u32))` if a key was stored
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_last_vtxo_key_index(&self) -> anyhow::Result<Option<u32>>;

	/// Retrieves the derivation index of the provided [PublicKey] from the database
	///
	/// Returns:
	/// - `Ok(Some(u32))` if the key was stored.
	/// - `Ok(None)` if the key was not stored.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_public_key_idx(&self, public_key: &PublicKey) -> anyhow::Result<Option<u32>>;

	/// Store a new pending lightning send.
	///
	/// Parameters:
	/// - invoice: The invoice of the pending lightning send.
	/// - amount: The amount of the pending lightning send.
	/// - vtxos: The vtxos of the pending lightning send.
	///
	/// Errors:
	/// - Returns an error if the pending lightning send cannot be stored.
	fn store_new_pending_lightning_send(&self, invoice: &Invoice, amount: &Amount, vtxos: &[VtxoId])
		-> anyhow::Result<PendingLightningSend>;

	/// Get all pending lightning sends.
	///
	/// Returns:
	/// - `Ok(Vec<PendingLightningSend>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_all_pending_lightning_send(&self) -> anyhow::Result<Vec<PendingLightningSend>>;

	/// Remove a pending lightning send.
	///
	/// Parameters:
	/// - payment_hash: The [PaymentHash] of the pending lightning send to remove.
	///
	/// Errors:
	/// - Returns an error if the pending lightning send cannot be removed.
	fn remove_pending_lightning_send(&self, payment_hash: PaymentHash) -> anyhow::Result<()>;

	/// Store an incoming Lightning receive record.
	///
	/// Parameters:
	/// - payment_hash: Unique payment hash.
	/// - preimage: Payment preimage (kept until disclosure).
	/// - invoice: The associated BOLT11 invoice.
	///
	/// Errors:
	/// - Returns an error if the receive cannot be stored.
	fn store_lightning_receive(
		&self,
		payment_hash: PaymentHash,
		preimage: Preimage,
		invoice: &Bolt11Invoice,
	) -> anyhow::Result<()>;

	/// Returns a list of all pending lightning receives
	///
	/// Returns:
	/// - `Ok(Vec<LightningReceive>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_all_pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>>;

	/// Mark a Lightning receive preimage as revealed (e.g., after settlement).
	///
	/// Parameters:
	/// - payment_hash: The payment hash identifying the receive.
	///
	/// Errors:
	/// - Returns an error if the update fails or the receive does not exist.
	fn set_preimage_revealed(&self, payment_hash: PaymentHash) -> anyhow::Result<()>;

	/// Set the VTXO IDs for a Lightning receive.
	///
	/// Parameters:
	/// - payment_hash: The payment hash identifying the receive.
	/// - htlc_vtxo_ids: The VTXO IDs to set.
	///
	/// Errors:
	/// - Returns an error if the update fails or the receive does not exist.
	fn set_lightning_receive_vtxos(&self, payment_hash: PaymentHash, htlc_vtxo_ids: &[VtxoId])
		-> anyhow::Result<()>;

	/// Fetch a Lightning receive by its payment hash.
	///
	/// Parameters:
	/// - payment_hash: The payment hash to look up.
	///
	/// Returns:
	/// - `Ok(Some(LightningReceive))` if found,
	/// - `Ok(None)` otherwise.
	///
	/// Errors:
	/// - Returns an error if the lookup fails.
	fn fetch_lightning_receive_by_payment_hash(&self, payment_hash: PaymentHash) -> anyhow::Result<Option<LightningReceive>>;

	/// Remove a Lightning receive by its payment hash.
	///
	/// Parameters:
	/// - payment_hash: The payment hash of the record to remove.
	///
	/// Errors:
	/// - Returns an error if the removal fails.
	fn remove_pending_lightning_receive(&self, payment_hash: PaymentHash) -> anyhow::Result<()>;

	/// Store an entry indicating a [Vtxo] is being exited.
	///
	/// Parameters:
	/// - exit: StoredExit describing the exit operation.
	///
	/// Errors:
	/// - Returns an error if the entry cannot be stored.
	fn store_exit_vtxo_entry(&self, exit: &StoredExit) -> anyhow::Result<()>;

	/// Remove an exit entry for a given [Vtxo] ID.
	///
	/// Parameters:
	/// - id: VtxoId to remove from exit tracking.
	///
	/// Errors:
	/// - Returns an error if the removal fails.
	fn remove_exit_vtxo_entry(&self, id: &VtxoId) -> anyhow::Result<()>;

	/// List all VTXOs currently tracked as being exited.
	///
	/// Returns:
	/// - `Ok(Vec<StoredExit>)` possibly empty.
	///
	/// Errors:
	/// - Returns an error if the query fails.
	fn get_exit_vtxo_entries(&self) -> anyhow::Result<Vec<StoredExit>>;

	/// Store a child transaction related to an exit transaction.
	///
	/// Parameters:
	/// - exit_txid: The parent exit transaction ID.
	/// - child_tx: The child bitcoin Transaction to store.
	/// - origin: Metadata describing where the child came from (ExitTxOrigin).
	///
	/// Errors:
	/// - Returns an error if the transaction cannot be stored.
	fn store_exit_child_tx(
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
	fn get_exit_child_tx(
		&self,
		exit_txid: Txid,
	) -> anyhow::Result<Option<(Transaction, ExitTxOrigin)>>;

	fn update_vtxo_state_checked(
		&self,
		vtxo_id: VtxoId,
		new_state: VtxoState,
		allowed_old_states: &[VtxoStateKind],
	) -> anyhow::Result<WalletVtxo>;
}
