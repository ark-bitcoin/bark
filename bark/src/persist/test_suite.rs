//! Shared test suite for [BarkPersister] implementations.
//!
//! Every test is defined once as a `pub async fn` taking a fresh, empty
//! persister.  A backend instantiates the whole suite with
//! [bark_persister_tests!], which generates one test function per case.

use std::str::FromStr;

use bitcoin::bip32::Fingerprint;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, ScriptBuf, Transaction};
use bitcoin::hashes::Hash;

use bitcoin_ext::BlockRef;
use lightning_invoice::Bolt11Invoice;

use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::test_util::VTXO_VECTORS;
use ark::VtxoId;

use super::BarkPersister;
use crate::actions::WalletActionCheckpoint;
use crate::actions::lightning::pay::{Htlcs, LightningSend, Progress, Revocation};
use crate::exit::{
	ExitProcessingState, ExitState, ExitStateKind, ExitTx, ExitTxOrigin, ExitTxStatus,
};
use crate::movement::{
	Movement, MovementDestination, MovementId, MovementStatus, MovementSubsystem, PaymentMethod,
};
use crate::movement::update::MovementUpdate;
use crate::persist::models::{SerdeRoundState, StoredExit, StoredRoundState, Unlocked};
use crate::lock_manager::LockManager;
use crate::lock_manager::memory::MemoryLockManager;
use crate::round::{RoundFlowState, RoundParticipation, RoundState};
use crate::vtxo::{VtxoState, VtxoStateKind, WalletVtxo};
use crate::WalletProperties;

// ---------------------------------------------------------------------------
// Suite instantiation
// ---------------------------------------------------------------------------

/// Generate one test per suite case against a backend.
///
/// `$setup` is an `async fn(&str) -> (guard, persister)` returning a fresh,
/// empty persister; the argument is the test name, for backends that need a
/// distinct store per test (IndexedDB databases are named and persistent).
/// The guard is kept alive for the duration of the test.
macro_rules! bark_persister_tests {
	(@tests $setup:expr, $($name:ident),* $(,)?) => {
		$(
			#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
			#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
			async fn $name() {
				let (_ctx, db) = $setup(stringify!($name)).await;
				crate::persist::test_suite::$name(&db).await;
			}
		)*
	};
	($setup:expr) => {
		$crate::persist::test_suite::bark_persister_tests!(@tests $setup,
			test_init_and_read_properties,
			test_set_server_pubkey,
			test_set_server_mailbox_pubkey,

			test_mailbox_checkpoint_empty_db,
			test_mailbox_checkpoint_roundtrip,
			test_vtxo_keys_empty,
			test_vtxo_key_roundtrip,
			test_vtxo_key_last_index_advances,

			test_store_and_get_vtxo,
			test_get_vtxos_by_state,
			test_vtxo_state_transition_ok,
			test_vtxo_state_transition_repeated,
			test_vtxo_state_transition_rejected,
			test_vtxo_state_transition_holder_upgrade,
			test_remove_vtxo,
			test_has_spent_vtxo,
			test_store_vtxos_idempotent,

			test_create_and_get_movement,
			test_update_movement,
			test_get_all_movements,
			test_get_movements_by_payment_method,
			test_get_or_create_movement_for_action,

			test_store_and_get_round_state,
			test_update_round_state,
			test_remove_round_state,

			test_wallet_action_checkpoint_upsert_and_get,
			test_wallet_action_checkpoint_upsert_replaces,
			test_wallet_action_checkpoint_get_missing,
			test_wallet_action_checkpoint_get_all,
			test_wallet_action_checkpoint_remove,
			test_wallet_action_checkpoint_remove_missing_is_noop,
			test_paid_invoice_record_and_get,
			test_paid_invoice_record_is_idempotent,
			test_paid_invoice_get_missing,
			test_settled_lightning_receive_record_and_get,
			test_settled_lightning_receive_record_is_idempotent,
			test_settled_lightning_receive_get_missing,

			test_exit_vtxo_entry_roundtrip,
			test_exit_processing_state_roundtrip,
			test_exit_child_tx_roundtrip,
			test_exit_entries_with_states,
		);
	};
}
pub(crate) use bark_persister_tests;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_properties() -> WalletProperties {
	WalletProperties {
		network: Network::Regtest,
		fingerprint: Fingerprint::default(),
		server_pubkey: None,
		server_mailbox_pubkey: None,
	}
}

// A known-valid BOLT11 invoice on signet (from test data in payment_method.rs)
const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

/// An ark address
const ARK_ADDR: &str = "tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z";

fn test_bolt11() -> Bolt11Invoice {
	Bolt11Invoice::from_str(TEST_INVOICE_STR).expect("valid test invoice")
}

fn test_invoice() -> Invoice {
	Invoice::Bolt11(test_bolt11())
}

fn test_preimage() -> Preimage {
	Preimage::from_slice(&[3u8; 32]).unwrap()
}

fn test_subsystem() -> MovementSubsystem {
	MovementSubsystem {
		name: "test-subsystem".into(),
		kind: "test-kind".into(),
	}
}

fn empty_tx() -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::TWO,
		lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	}
}

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
	let secp = Secp256k1::new();
	let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
	Keypair::from_secret_key(&secp, &sk).public_key()
}

/// Returns `now` truncated to millisecond precision.
///
/// SQLite stores timestamps as `%Y-%m-%d %H:%M:%f` (millisecond precision).
/// Using a pre-truncated value ensures the stored timestamp round-trips equal
/// to the input.
fn test_time() -> chrono::DateTime<chrono::Local> {
	let ms = chrono::Local::now().timestamp_millis();
	chrono::DateTime::from_timestamp_millis(ms)
		.unwrap()
		.with_timezone(&chrono::Local)
}

fn empty_round_state() -> RoundState {
	RoundState {
		done: false,
		participation: RoundParticipation {
			inputs: vec![],
			outputs: vec![],
			unblinded_mailbox_id: None,
		},
		flow: RoundFlowState::InteractivePending,
		new_vtxos: vec![],
		sent_forfeit_sigs: false,
		movement_id: None,
	}
}

fn send_at_start() -> LightningSend {
	LightningSend {
		invoice: test_invoice(),
		original_payment_method: PaymentMethod::Custom("test".into()),
		input_vtxo_ids: vec![],
		payment_amount: Amount::from_sat(1000),
		fee: Amount::from_sat(10),
		change_pieces: Some(vec![Amount::from_sat(500), Amount::from_sat(500)]),
		htlc_key: test_pubkey(),
		htlc_expiry: 100,
		movement_id: Some(MovementId::new(1)),
		revocation_key: Some(test_pubkey()),
		progress: Progress::Start,
		allow_exit_of_htlcs: false,
	}
}

fn send_at_htlc_received() -> LightningSend {
	LightningSend {
		progress: Progress::HtlcReceived(Htlcs {
			vtxo_ids: vec![],
			mailbox_id: ark::mailbox::MailboxIdentifier::from(test_pubkey()),
			movement_id: MovementId::new(1),
		}),
		..send_at_start()
	}
}

fn send_at_payment_initiated() -> LightningSend {
	let progress = match send_at_htlc_received().progress {
		Progress::HtlcReceived(htlcs) => Progress::PaymentInitiated(htlcs),
		_ => unreachable!(),
	};
	LightningSend { progress, ..send_at_start() }
}

fn send_at_revocable_htlcs() -> LightningSend {
	let htlcs = match send_at_htlc_received().progress {
		Progress::HtlcReceived(htlcs) => htlcs,
		_ => unreachable!(),
	};
	LightningSend {
		progress: Progress::RevocableHtlcs {
			htlcs,
			revocation: Revocation { key: test_pubkey() },
		},
		..send_at_start()
	}
}

fn paid_invoice_hash() -> PaymentHash {
	PaymentHash::from_slice(&[0xcdu8; 32]).unwrap()
}

fn settled_receive_hash() -> PaymentHash {
	PaymentHash::from_slice(&[0xefu8; 32]).unwrap()
}

fn test_exit_vtxo_id() -> VtxoId {
	VtxoId::from_slice(&[0xeeu8; 36]).unwrap()
}

fn test_exit_txid() -> bitcoin::Txid {
	bitcoin::Txid::from_slice(&[0xffu8; 32]).unwrap()
}

/// Compare a stored round state against the state it was built from.
///
/// `RoundState` does not derive `PartialEq` or `Serialize` because
/// `RoundFlowState` contains `Keypair` and `SecretNonce`.  We compare the
/// fields that survive a round-trip through `SerdeRoundState`.
fn round_states_match(stored: &StoredRoundState<Unlocked>, expected: &RoundState) -> bool {
	let stored_json = serde_json::to_string(&SerdeRoundState::from(stored.state()))
		.expect("SerdeRoundState serialization failed for the stored state");
	let expected_json = serde_json::to_string(&SerdeRoundState::from(expected))
		.expect("SerdeRoundState serialization failed for the expected state");
	stored_json == expected_json
}

/// Asserts the documented order: expiry height ASC, then amount DESC.
fn assert_vtxo_order(vtxos: &[WalletVtxo], ctx: &str) {
	let ordered = vtxos.is_sorted_by(|a, b| {
		a.vtxo.expiry_height().cmp(&b.vtxo.expiry_height())
			.then(b.vtxo.amount().cmp(&a.vtxo.amount())) != std::cmp::Ordering::Greater
	});
	assert!(ordered, "{ctx}: not sorted by expiry_height ASC, amount DESC");
}

// ---------------------------------------------------------------------------
// Wallet properties
// ---------------------------------------------------------------------------

pub async fn test_init_and_read_properties(db: &impl BarkPersister) {
	let props = test_properties();
	db.init_wallet(&props).await.expect("init_wallet");

	let read = db.read_properties().await.expect("read_properties");
	assert_eq!(read, Some(props), "read_properties should return the stored properties");
}

pub async fn test_set_server_pubkey(db: &impl BarkPersister) {
	db.init_wallet(&test_properties()).await.expect("init_wallet");
	let pk = test_pubkey();

	db.set_server_pubkey(pk).await.expect("set_server_pubkey");

	let read = db.read_properties().await.expect("read_properties").expect("properties present");
	assert_eq!(read, WalletProperties { server_pubkey: Some(pk), ..test_properties() });
}

pub async fn test_set_server_mailbox_pubkey(db: &impl BarkPersister) {
	db.init_wallet(&test_properties()).await.expect("init_wallet");
	let pk = test_pubkey();

	db.set_server_mailbox_pubkey(pk).await.expect("set_server_mailbox_pubkey");

	let read = db.read_properties().await.expect("read_properties").expect("properties present");
	assert_eq!(read, WalletProperties { server_mailbox_pubkey: Some(pk), ..test_properties() });
}

// ---------------------------------------------------------------------------
// VTXO keys and mailbox checkpoint
// ---------------------------------------------------------------------------

pub async fn test_mailbox_checkpoint_empty_db(db: &impl BarkPersister) {
	let checkpoint = db.get_mailbox_checkpoint().await.expect("get_mailbox_checkpoint");
	assert_eq!(checkpoint, 0, "get_mailbox_checkpoint (empty db) should be 0");
}

pub async fn test_mailbox_checkpoint_roundtrip(db: &impl BarkPersister) {
	db.store_mailbox_checkpoint(42).await.expect("store_mailbox_checkpoint");

	let checkpoint = db.get_mailbox_checkpoint().await.expect("get_mailbox_checkpoint");
	assert_eq!(checkpoint, 42, "stored checkpoint should be returned");
}

pub async fn test_vtxo_keys_empty(db: &impl BarkPersister) {
	let pk = test_pubkey();

	let last = db.get_last_vtxo_key_index().await.expect("get_last_vtxo_key_index");
	assert_eq!(last, None, "an empty db has no vtxo key index");

	let idx = db.get_public_key_idx(&pk).await.expect("get_public_key_idx");
	assert_eq!(idx, None, "an unknown public key has no index");
}

pub async fn test_vtxo_key_roundtrip(db: &impl BarkPersister) {
	let pk = test_pubkey();

	db.store_vtxo_key(0, pk).await.expect("store_vtxo_key");

	let last = db.get_last_vtxo_key_index().await.expect("get_last_vtxo_key_index");
	assert_eq!(last, Some(0), "last index after storing index 0");

	let idx = db.get_public_key_idx(&pk).await.expect("get_public_key_idx");
	assert_eq!(idx, Some(0), "stored public key maps back to its index");
}

pub async fn test_vtxo_key_last_index_advances(db: &impl BarkPersister) {
	let secp = Secp256k1::new();
	for i in 0u32..=2 {
		let seed = u8::try_from(i).unwrap() + 10;
		let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
		let pk = Keypair::from_secret_key(&secp, &sk).public_key();
		db.store_vtxo_key(i, pk).await.expect("store_vtxo_key");
	}

	let last = db.get_last_vtxo_key_index().await.expect("get_last_vtxo_key_index");
	assert_eq!(last, Some(2), "last index after storing indices 0..=2");
}

// ---------------------------------------------------------------------------
// VTXO lifecycle
// ---------------------------------------------------------------------------

pub async fn test_store_and_get_vtxo(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.board_vtxo;

	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("store_vtxos");

	let stored = db.get_wallet_vtxo(vtxo.id()).await.expect("get_wallet_vtxo")
		.expect("stored vtxo present");
	assert_eq!(stored.vtxo.id(), vtxo.id(), "stored vtxo round-trip");
	assert_eq!(stored.state, VtxoState::Spendable, "stored state round-trip");

	let fetched = db.get_wallet_vtxos(&[vtxo.id()]).await.expect("get_wallet_vtxos");
	assert_eq!(fetched, vec![stored.clone()], "get_wallet_vtxos returns the stored vtxo");

	let duplicated = db.get_wallet_vtxos(&[vtxo.id(), vtxo.id()]).await
		.expect("get_wallet_vtxos with duplicate id");
	assert_eq!(duplicated.len(), 2, "a repeated id yields the vtxo once per occurrence");

	assert!(db.get_wallet_vtxos(&[VTXO_VECTORS.round1_vtxo.id()]).await.is_err(),
		"get_wallet_vtxos should error on a missing id");

	let all = db.get_all_vtxos().await.expect("get_all_vtxos");
	assert_eq!(all, vec![stored], "get_all_vtxos returns every stored vtxo");
}

pub async fn test_get_vtxos_by_state(db: &impl BarkPersister) {
	// All vectors share the same expiry height, so amount decides the order.
	// The spent vtxo (9000 sat) sorts between the board vtxo (10_330 sat) and
	// the other spendable one (8000 sat), so results grouped by state would
	// fail the order check.
	let big = &VTXO_VECTORS.board_vtxo;
	let small = &VTXO_VECTORS.arkoor2_vtxo;
	let spent = &VTXO_VECTORS.arkoor_htlc_out_vtxo;

	db.store_vtxos(&[
		(big, &VtxoState::Spendable),
		(small, &VtxoState::Spendable),
		(spent, &VtxoState::Spent),
	]).await.expect("store_vtxos");

	let spendable = db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await
		.expect("get_vtxos_by_state");
	assert_vtxo_order(&spendable, "get_vtxos_by_state (spendable)");
	assert_eq!(
		spendable.iter().map(|v| v.vtxo.id()).collect::<Vec<_>>(),
		vec![big.id(), small.id()],
		"only spendable vtxos, ordered by amount",
	);

	// Multi-state queries must be globally ordered, not grouped by state.
	let states = [VtxoStateKind::Spendable, VtxoStateKind::Spent];
	let all = db.get_vtxos_by_state(&states).await.expect("get_vtxos_by_state");
	assert_vtxo_order(&all, "get_vtxos_by_state (multi-state)");
	assert_eq!(
		all.iter().map(|v| v.vtxo.id()).collect::<Vec<_>>(),
		vec![big.id(), spent.id(), small.id()],
		"multi-state query is ordered across states",
	);
}

pub async fn test_vtxo_state_transition_ok(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.round1_vtxo;
	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("store_vtxos");

	let updated = db
		.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, VtxoStateKind::UNSPENT_STATES)
		.await.expect("update_vtxo_state_checked");
	assert_eq!(updated.state, VtxoState::Spent, "the new state is persisted");
}

/// Repeating a transition that already took effect must be an accepted no-op,
/// so an interrupted operation can be retried.  The two calls differ in whether
/// the target kind is itself listed as an allowed old state: neither may error,
/// and neither may change the state.
pub async fn test_vtxo_state_transition_repeated(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.round1_vtxo;
	db.store_vtxos(&[(vtxo, &VtxoState::Spent)]).await.expect("store_vtxos");

	// Target kind absent from the allowed old states. The guard would reject
	// this were the vtxo not already in the target state.
	let updated = db
		.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, VtxoStateKind::UNSPENT_STATES)
		.await.expect("repeating a transition must be a no-op, not an error");
	assert_eq!(updated.state, VtxoState::Spent, "repeated transition must leave the state alone");

	// Target kind present in the allowed old states, so the guard passes and
	// only the already-applied check prevents a redundant write.
	let updated = db
		.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Spent])
		.await.expect("self-transition on an already-spent vtxo");
	assert_eq!(updated.state, VtxoState::Spent, "self-transition must leave the state alone");
}

pub async fn test_vtxo_state_transition_rejected(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.round2_vtxo;
	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("store_vtxos");

	let result = db
		.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Spent]).await;
	assert!(result.is_err(), "transition from Spendable with only Spent allowed should be rejected");

	let stored = db.get_wallet_vtxo(vtxo.id()).await.expect("get_wallet_vtxo").unwrap();
	assert_eq!(stored.state, VtxoState::Spendable, "a rejected transition must not change the state");
}

/// Transitioning within the same `state_kind` must still take effect:
/// attaching a holder to a `Locked { holder: None }` row is a real state change.
pub async fn test_vtxo_state_transition_holder_upgrade(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
	db.store_vtxos(&[(vtxo, &VtxoState::Locked { holder: None })]).await.expect("store_vtxos");

	let target = VtxoState::Locked {
		holder: Some(MovementId::new(42).into()),
	};
	let updated = db.update_vtxo_state_checked(vtxo.id(), target.clone(), &[VtxoStateKind::Locked])
		.await.expect("holder upgrade");
	assert_eq!(updated.state, target, "the new state is persisted");
}

pub async fn test_remove_vtxo(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.arkoor3_vtxo;
	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("store_vtxos");

	let removed = db.remove_vtxo(vtxo.id()).await.expect("remove_vtxo");
	assert_eq!(removed.as_ref(), Some(vtxo), "remove_vtxo returns the removed vtxo");

	let stored = db.get_wallet_vtxo(vtxo.id()).await.expect("get_wallet_vtxo after remove");
	assert_eq!(stored, None, "the vtxo is gone after remove");
}

pub async fn test_has_spent_vtxo(db: &impl BarkPersister) {
	let spent = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
	db.store_vtxos(&[(spent, &VtxoState::Spent)]).await.expect("store_vtxos");

	assert!(db.has_spent_vtxo(spent.id()).await.expect("has_spent_vtxo"),
		"a vtxo in Spent state is reported as spent");

	let unknown_id = VtxoId::from_slice(&[0u8; 36]).unwrap();
	assert!(!db.has_spent_vtxo(unknown_id).await.expect("has_spent_vtxo (unknown)"),
		"an unknown vtxo is not reported as spent");
}

pub async fn test_store_vtxos_idempotent(db: &impl BarkPersister) {
	let vtxo = &VTXO_VECTORS.board_vtxo;

	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("initial store_vtxos");
	db.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("repeated store_vtxos");

	let stored = db.get_wallet_vtxo(vtxo.id()).await.expect("get_wallet_vtxo").unwrap();
	assert_eq!(stored.vtxo.id(), vtxo.id(), "the vtxo survives a repeated store");
	assert_eq!(stored.state, VtxoState::Spendable, "the state survives a repeated store");
	assert_eq!(db.get_all_vtxos().await.expect("get_all_vtxos").len(), 1,
		"a repeated store must not insert a second row");
}

// ---------------------------------------------------------------------------
// Movements
// ---------------------------------------------------------------------------

pub async fn test_create_and_get_movement(db: &impl BarkPersister) {
	let subsystem = test_subsystem();
	let time = test_time();

	let id = db.create_new_movement(MovementStatus::Pending, &subsystem, time, None).await
		.expect("create_new_movement");

	let movement = db.get_movement_by_id(id).await.expect("get_movement_by_id");
	assert_eq!(movement, Movement::new(id, MovementStatus::Pending, &subsystem, time),
		"a freshly created movement carries only its creation arguments");
}

pub async fn test_update_movement(db: &impl BarkPersister) {
	let time = test_time();
	let id = db.create_new_movement(MovementStatus::Pending, &test_subsystem(), time, None).await
		.expect("create_new_movement");

	let mut movement = db.get_movement_by_id(id).await.expect("get_movement_by_id");
	movement.status = MovementStatus::Successful;
	movement.intended_balance = bitcoin::SignedAmount::from_sat(1000);
	db.update_movement(&movement).await.expect("update_movement");

	let stored = db.get_movement_by_id(id).await.expect("get_movement_by_id after update");
	assert_eq!(stored.status, MovementStatus::Successful, "status update is persisted");
	assert_eq!(stored.intended_balance, bitcoin::SignedAmount::from_sat(1000),
		"intended balance update is persisted");
}

pub async fn test_get_all_movements(db: &impl BarkPersister) {
	let subsystem = test_subsystem();
	let time = test_time();

	let pending = db.create_new_movement(MovementStatus::Pending, &subsystem, time, None).await
		.expect("create_new_movement 1");
	let failed = db.create_new_movement(MovementStatus::Failed, &subsystem, time, None).await
		.expect("create_new_movement 2");

	let mut all = db.get_all_movements().await.expect("get_all_movements");
	all.sort_by_key(|m| m.id.0);
	assert_eq!(
		all.iter().map(|m| (m.id, m.status)).collect::<Vec<_>>(),
		vec![(pending, MovementStatus::Pending), (failed, MovementStatus::Failed)],
		"every created movement is returned",
	);
}

pub async fn test_get_movements_by_payment_method(db: &impl BarkPersister) {
	let subsystem = test_subsystem();
	let time = test_time();
	let addr = ark::Address::from_str(ARK_ADDR).unwrap();

	let ark_id = db.create_new_movement(MovementStatus::Pending, &subsystem, time, None).await.unwrap();
	let mut m = db.get_movement_by_id(ark_id).await.unwrap();
	m.received_on = vec![MovementDestination {
		destination: PaymentMethod::Ark(addr.clone()),
		amount: Amount::ONE_BTC,
	}];
	db.update_movement(&m).await.unwrap();

	let script_id = db.create_new_movement(MovementStatus::Pending, &subsystem, time, None).await.unwrap();
	let mut m = db.get_movement_by_id(script_id).await.unwrap();
	m.received_on = vec![MovementDestination {
		destination: PaymentMethod::OutputScript(ScriptBuf::new_p2a()),
		amount: Amount::ONE_BTC,
	}];
	db.update_movement(&m).await.unwrap();

	let found = db.get_movements_by_payment_method(&PaymentMethod::Ark(addr.clone())).await.unwrap();
	let [m] = found.try_into().unwrap();
	assert_eq!(m.id, ark_id);

	let found = db.get_movements_by_payment_method(
		&PaymentMethod::OutputScript(ScriptBuf::new_p2a()),
	).await.unwrap();
	let [m] = found.try_into().unwrap();
	assert_eq!(m.id, script_id);
}

pub async fn test_get_or_create_movement_for_action(db: &impl BarkPersister) {
	let subsystem = test_subsystem();
	let time = test_time();
	let action_id = "ln_recv.reentrancy";
	let balance = bitcoin::SignedAmount::from_sat(4_200);

	// The first call creates the movement and applies the initial update atomically.
	let (id, created) = db.get_or_create_movement_for_action(
		&subsystem, time, action_id, MovementUpdate::new().intended_balance(balance),
	).await.expect("first get_or_create");
	assert!(created, "first call should report a creation");

	let movement = db.get_movement_by_id(id).await.expect("get after create");
	assert_eq!(movement.intended_balance, balance, "initial update was not applied");

	// A re-drive reuses the same movement instead of inserting a duplicate,
	// and does not re-apply the update.
	let (again, recreated) = db.get_or_create_movement_for_action(
		&subsystem, time, action_id,
		MovementUpdate::new().intended_balance(bitcoin::SignedAmount::from_sat(9_001)),
	).await.expect("second get_or_create");
	assert!(!recreated, "second call should reuse the movement");
	assert_eq!(again, id, "reused movement id mismatch");

	let movement = db.get_movement_by_id(id).await.expect("get after reuse");
	assert_eq!(movement.intended_balance, balance, "reuse must not re-apply the update");
}

// ---------------------------------------------------------------------------
// Round states
// ---------------------------------------------------------------------------

pub async fn test_store_and_get_round_state(db: &impl BarkPersister) {
	let state = empty_round_state();

	let id = db.store_round_state(&state).await.expect("store_round_state");

	let pending = db.get_pending_round_state_ids().await.expect("get_pending_round_state_ids");
	assert_eq!(pending, vec![id], "the stored round state is pending");

	let stored = db.get_round_state_by_id(id).await.expect("get_round_state_by_id")
		.expect("stored round state present");
	assert_eq!(stored.id(), id, "stored round state id");
	assert!(round_states_match(&stored, &state), "stored round state differs from the input");
}

pub async fn test_update_round_state(db: &impl BarkPersister) {
	let id = db.store_round_state(&empty_round_state()).await.expect("store_round_state");
	let unlocked = db.get_round_state_by_id(id).await.expect("get_round_state_by_id").unwrap();

	let mgr = MemoryLockManager::new();
	let guard = mgr.try_lock("test.round").await.expect("test.round unlocked");
	let mut locked = unlocked.lock(guard);
	locked.state_mut().done = true;
	db.update_round_state(&locked).await.expect("update_round_state");

	let expected = RoundState { done: true, ..empty_round_state() };
	let stored = db.get_round_state_by_id(id).await.expect("get_round_state_by_id after update")
		.expect("round state still present");
	assert!(round_states_match(&stored, &expected), "the update was not persisted");
}

pub async fn test_remove_round_state(db: &impl BarkPersister) {
	let id = db.store_round_state(&empty_round_state()).await.expect("store_round_state");
	let unlocked = db.get_round_state_by_id(id).await.expect("get_round_state_by_id").unwrap();

	let mgr = MemoryLockManager::new();
	let guard = mgr.try_lock("test.round").await.expect("test.round unlocked");
	db.remove_round_state(&unlocked.lock(guard)).await.expect("remove_round_state");

	let stored = db.get_round_state_by_id(id).await.expect("get_round_state_by_id after remove");
	assert!(stored.is_none(), "get_round_state_by_id should be None after remove");

	let pending = db.get_pending_round_state_ids().await
		.expect("get_pending_round_state_ids after remove");
	assert!(pending.is_empty(), "a removed round state is no longer pending");
}

// ---------------------------------------------------------------------------
// Lightning
// ---------------------------------------------------------------------------

/// A checkpoint persisted before `movement_id`/`revocation_key`/
/// `change_pieces` existed has no such fields; `#[serde(default)]` must
/// load them as `None` not fail.
#[test]
fn legacy_checkpoint_missing_optional_fields_default_to_none() {
	let checkpoint = WalletActionCheckpoint::from(send_at_start());
	let mut json = serde_json::to_value(&checkpoint).expect("serialize checkpoint");
	// Drop the fields to mimic a checkpoint written before they were added.
	let obj = json["LightningSend"].as_object_mut().expect("LightningSend object");
	assert!(obj.remove("movement_id").is_some(), "fixture should carry a movement_id");
	assert!(obj.remove("revocation_key").is_some(), "fixture should carry a revocation_key");
	assert!(obj.remove("change_pieces").is_some(), "fixture should carry change_pieces");

	let restored: WalletActionCheckpoint =
		serde_json::from_value(json).expect("deserialize legacy checkpoint");
	let send = restored.into_lightning_send().unwrap();
	assert_eq!(send.movement_id, None);
	assert_eq!(send.revocation_key, None);
	assert_eq!(send.change_pieces, None);
}

pub async fn test_wallet_action_checkpoint_upsert_and_get(db: &impl BarkPersister) {
	let checkpoint: WalletActionCheckpoint = send_at_start().into();
	let id = checkpoint.id();

	db.upsert_wallet_action_checkpoint(&id, &checkpoint).await.expect("upsert");

	let stored = db.get_wallet_action_checkpoint(&id).await
		.expect("get_wallet_action_checkpoint");
	assert_eq!(stored, Some(checkpoint), "stored checkpoint round-trip mismatch");
}

pub async fn test_wallet_action_checkpoint_upsert_replaces(db: &impl BarkPersister) {
	let start: WalletActionCheckpoint = send_at_start().into();
	let id = start.id();
	db.upsert_wallet_action_checkpoint(&id, &start).await.unwrap();

	let initiated: WalletActionCheckpoint = send_at_payment_initiated().into();
	assert_eq!(initiated.id(), id, "different phases of the same invoice must share an id");
	db.upsert_wallet_action_checkpoint(&id, &initiated).await.expect("replace");

	let stored = db.get_wallet_action_checkpoint(&id).await.unwrap();
	assert_eq!(stored, Some(initiated), "replaced checkpoint should match latest upsert");
}

pub async fn test_wallet_action_checkpoint_get_missing(db: &impl BarkPersister) {
	let id = "missing-checkpoint-id".to_string();
	let stored = db.get_wallet_action_checkpoint(&id).await.unwrap();
	assert!(stored.is_none(), "expected None");
}

pub async fn test_wallet_action_checkpoint_get_all(db: &impl BarkPersister) {
	let revocable: WalletActionCheckpoint = send_at_revocable_htlcs().into();
	let id = revocable.id();
	db.upsert_wallet_action_checkpoint(&id, &revocable).await.unwrap();

	let all = db.get_all_wallet_action_checkpoints().await.unwrap();
	assert_eq!(all, vec![revocable], "get_all returns every stored checkpoint");
}

pub async fn test_wallet_action_checkpoint_remove(db: &impl BarkPersister) {
	let received: WalletActionCheckpoint = send_at_htlc_received().into();
	let id = received.id();
	db.upsert_wallet_action_checkpoint(&id, &received).await.unwrap();

	db.remove_wallet_action_checkpoint(&id).await.unwrap();

	let stored = db.get_wallet_action_checkpoint(&id).await.unwrap();
	assert!(stored.is_none(), "checkpoint should be gone after remove");
}

pub async fn test_wallet_action_checkpoint_remove_missing_is_noop(db: &impl BarkPersister) {
	let id = "never-existed".to_string();
	db.remove_wallet_action_checkpoint(&id).await
		.expect("remove of missing id should not error");
}

pub async fn test_paid_invoice_record_and_get(db: &impl BarkPersister) {
	let hash = paid_invoice_hash();
	let preimage = test_preimage();

	db.record_paid_invoice(hash, preimage).await.unwrap();

	let stored = db.get_paid_invoice(hash).await.expect("get_paid_invoice")
		.expect("should have stored row");
	assert_eq!(stored.payment_hash, hash, "payment hash round-trip");
	assert_eq!(stored.preimage, preimage, "preimage round-trip");
}

pub async fn test_paid_invoice_record_is_idempotent(db: &impl BarkPersister) {
	let hash = paid_invoice_hash();
	let preimage = test_preimage();

	db.record_paid_invoice(hash, preimage).await.unwrap();
	db.record_paid_invoice(hash, preimage).await
		.expect("second record_paid_invoice should be a no-op");

	let stored = db.get_paid_invoice(hash).await.unwrap().expect("row still present");
	assert_eq!(stored.preimage, preimage, "preimage stable across retry");
}

pub async fn test_paid_invoice_get_missing(db: &impl BarkPersister) {
	let hash = PaymentHash::from_slice(&[0x55u8; 32]).unwrap();
	let stored = db.get_paid_invoice(hash).await.unwrap();
	assert!(stored.is_none(), "missing hash returns None");
}

pub async fn test_settled_lightning_receive_record_and_get(db: &impl BarkPersister) {
	let hash = settled_receive_hash();
	let preimage = test_preimage();
	let invoice = test_bolt11();
	let amount = Amount::from_sat(12_345);

	db.record_settled_lightning_receive(hash, preimage, &invoice, amount).await.unwrap();

	let stored = db.get_settled_lightning_receive(hash).await.expect("get").expect("present");
	assert_eq!(stored.payment_hash, hash, "payment hash round-trip");
	assert_eq!(stored.preimage, preimage, "preimage round-trip");
	assert_eq!(stored.invoice, invoice, "invoice round-trip");
	assert_eq!(stored.amount, amount, "amount round-trip");
}

pub async fn test_settled_lightning_receive_record_is_idempotent(db: &impl BarkPersister) {
	let hash = settled_receive_hash();
	let preimage = test_preimage();
	let invoice = test_bolt11();

	db.record_settled_lightning_receive(hash, preimage, &invoice, Amount::from_sat(12_345))
		.await.unwrap();

	// A second record with a different amount must be a no-op: the original row wins.
	db.record_settled_lightning_receive(hash, preimage, &invoice, Amount::from_sat(999))
		.await.expect("second record should be a no-op");

	let stored = db.get_settled_lightning_receive(hash).await.unwrap().expect("row still present");
	assert_eq!(stored.amount, Amount::from_sat(12_345), "original amount preserved");
}

pub async fn test_settled_lightning_receive_get_missing(db: &impl BarkPersister) {
	let hash = PaymentHash::from_slice(&[0x66u8; 32]).unwrap();
	let stored = db.get_settled_lightning_receive(hash).await.unwrap();
	assert!(stored.is_none(), "missing hash returns None");
}

// ---------------------------------------------------------------------------
// Exit
// ---------------------------------------------------------------------------

pub async fn test_exit_vtxo_entry_roundtrip(db: &impl BarkPersister) {
	let vtxo_id = test_exit_vtxo_id();
	let entry = StoredExit {
		vtxo_id,
		state: ExitState::Start(crate::exit::ExitStartState { tip_height: 100 }),
		history: vec![],
		movement_id: None,
	};

	db.store_exit_vtxo_entry(&entry).await.expect("store_exit_vtxo_entry");

	let entries = db.get_exit_vtxo_entries().await.expect("get_exit_vtxo_entries");
	assert_eq!(entries.iter().collect::<Vec<_>>(), vec![&entry], "the stored entry is listed");

	let stored = db.get_exit_vtxo_entry(&vtxo_id).await.expect("get_exit_vtxo_entry");
	assert_eq!(stored.as_ref(), Some(&entry), "get_exit_vtxo_entry should return the stored entry");

	let unknown_id = VtxoId::from_slice(&[0xffu8; 36]).unwrap();
	let stored = db.get_exit_vtxo_entry(&unknown_id).await.expect("get_exit_vtxo_entry unknown");
	assert_eq!(stored, None, "get_exit_vtxo_entry should return None for an unknown VTXO");

	db.remove_exit_vtxo_entry(&vtxo_id).await.expect("remove_exit_vtxo_entry");

	let entries = db.get_exit_vtxo_entries().await.expect("get_exit_vtxo_entries after remove");
	assert!(entries.is_empty(), "the removed entry is no longer listed");

	let stored = db.get_exit_vtxo_entry(&vtxo_id).await.expect("get_exit_vtxo_entry after remove");
	assert_eq!(stored, None, "get_exit_vtxo_entry should return None after remove");
}

/// Persists a Processing state that touches every ExitTxStatus variant so any
/// rename or shape change to that enum is caught at the storage layer rather
/// than only at runtime.  Without this, a roundtrip-only test of ExitState::Start
/// (the trivial variant) lets schema-breaking refactors of nested variants slip
/// through silently.
pub async fn test_exit_processing_state_roundtrip(db: &impl BarkPersister) {
	let vtxo_id = VtxoId::from_slice(&[0xddu8; 36]).unwrap();
	let txid = |n: u8| bitcoin::Txid::from_slice(&[n; 32]).unwrap();
	let child_a = txid(0xa1);
	let child_b = txid(0xb1);
	let block = BlockRef {
		height: 12_345,
		hash: bitcoin::BlockHash::from_slice(&[0xcc; 32]).unwrap(),
	};

	let processing = ExitProcessingState {
		tip_height: 200,
		transactions: vec![
			ExitTx { txid: txid(0x01), status: ExitTxStatus::VerifyInputs },
			ExitTx {
				txid: txid(0x02),
				status: ExitTxStatus::AwaitingInputConfirmation {
					txids: [txid(0x03), txid(0x04)].into_iter().collect(),
				},
			},
			ExitTx { txid: txid(0x05), status: ExitTxStatus::AwaitingCpfpBroadcast },
			ExitTx {
				txid: txid(0x06),
				status: ExitTxStatus::AwaitingConfirmation {
					child_txid: child_a,
					origin: ExitTxOrigin::Wallet { confirmed_in: None },
				},
			},
			ExitTx {
				txid: txid(0x07),
				status: ExitTxStatus::Confirmed {
					child_txid: child_b,
					block,
					origin: ExitTxOrigin::Block { confirmed_in: block },
				},
			},
		],
	};
	let entry = StoredExit {
		vtxo_id,
		state: ExitState::Processing(processing),
		history: vec![ExitState::Start(crate::exit::ExitStartState { tip_height: 100 })],
		movement_id: None,
	};

	db.store_exit_vtxo_entry(&entry).await.expect("store processing entry");

	let entries = db.get_exit_vtxo_entries().await.expect("get_exit_vtxo_entries");
	assert_eq!(entries, vec![entry], "stored processing entry differs from input");
}

pub async fn test_exit_entries_with_states(db: &impl BarkPersister) {
	let start_id = VtxoId::from_slice(&[0xabu8; 36]).unwrap();
	let canceled_id = VtxoId::from_slice(&[0xacu8; 36]).unwrap();
	let entries = [
		StoredExit {
			vtxo_id: start_id,
			state: ExitState::Start(crate::exit::ExitStartState { tip_height: 100 }),
			history: vec![],
			movement_id: None,
		},
		StoredExit {
			vtxo_id: canceled_id,
			state: ExitState::new_canceled(150),
			history: vec![ExitState::Start(crate::exit::ExitStartState { tip_height: 100 })],
			movement_id: None,
		},
	];
	for entry in &entries {
		db.store_exit_vtxo_entry(entry).await.expect("store entry");
	}

	let cases: &[(&str, &[ExitStateKind], &[VtxoId])] = &[
		("canceled only", &[ExitStateKind::Canceled], &[canceled_id]),
		("start only", &[ExitStateKind::Start], &[start_id]),
		("both kinds", &[ExitStateKind::Start, ExitStateKind::Canceled], &[start_id, canceled_id]),
		("no matching kind", &[ExitStateKind::Claimed], &[]),
		("empty kind list", &[], &[]),
	];
	for (name, kinds, expected) in cases {
		let found = db.get_exit_vtxo_entries_with_states(kinds).await
			.expect("get_exit_vtxo_entries_with_states");

		let mut ids = found.into_iter().map(|e| e.vtxo_id).collect::<Vec<_>>();
		ids.sort();
		let mut expected = expected.to_vec();
		expected.sort();
		assert_eq!(ids, expected, "with_states wrong entries: {}", name);
	}
}

pub async fn test_exit_child_tx_roundtrip(db: &impl BarkPersister) {
	let txid = test_exit_txid();
	let child_tx = empty_tx();
	let origin = ExitTxOrigin::Wallet { confirmed_in: None };

	db.store_exit_child_tx(txid, &child_tx, origin.clone()).await.expect("store_exit_child_tx");

	let stored = db.get_exit_child_tx(txid).await.expect("get_exit_child_tx");
	assert_eq!(stored, Some((child_tx.clone(), origin)), "child tx round-trip");

	// Re-storing the same child must update the origin in place; the exit sync
	// relies on this to persist confirmation transitions.
	let confirmed_origin = ExitTxOrigin::Wallet {
		confirmed_in: Some(BlockRef {
			height: 54_321,
			hash: bitcoin::BlockHash::from_slice(&[0xabu8; 32]).unwrap(),
		}),
	};
	db.store_exit_child_tx(txid, &child_tx, confirmed_origin).await
		.expect("store_exit_child_tx origin update");

	let stored = db.get_exit_child_tx(txid).await.expect("get_exit_child_tx after origin update");
	assert_eq!(
		stored.map(|(_, o)| o),
		Some(confirmed_origin),
		"store_exit_child_tx should update the origin of an existing child",
	);

	// Re-storing a different child must replace the transaction as well.
	let replacement_tx = Transaction {
		lock_time: bitcoin::locktime::absolute::LockTime::from_consensus(1),
		..empty_tx()
	};
	db.store_exit_child_tx(txid, &replacement_tx, ExitTxOrigin::Mempool).await
		.expect("store_exit_child_tx replacement");

	let stored = db.get_exit_child_tx(txid).await.expect("get_exit_child_tx after replacement");
	assert_eq!(
		stored,
		Some((replacement_tx, ExitTxOrigin::Mempool)),
		"store_exit_child_tx should replace the child of an existing exit",
	);
}
