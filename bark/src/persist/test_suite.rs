//! Differential test suite for [BarkPersister] implementations.
//!
//! Call [run_all] with two freshly created persisters to verify that both
//! implementations satisfy the [BarkPersister] contract and produce identical
//! results for every operation.  Invoke this from a `#[tokio::test]` that
//! constructs one instance of each backend under test.

use std::str::FromStr;

use bitcoin::bip32::Fingerprint;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, Transaction};

use lightning_invoice::Bolt11Invoice;

use ark::lightning::{Invoice, PaymentHash, Preimage};
use ark::test_util::VTXO_VECTORS;
use ark::VtxoId;

use super::BarkPersister;
use crate::movement::{MovementStatus, MovementSubsystem};
use crate::persist::models::{SerdeRoundState, StoredRoundState, Unlocked};
use crate::round::RoundStateLockIndex;
use crate::round::{RoundFlowState, RoundParticipation, RoundState};
use crate::vtxo::{VtxoState, VtxoStateKind};
use crate::WalletProperties;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn test_properties() -> WalletProperties {
	WalletProperties {
		network: Network::Regtest,
		fingerprint: Fingerprint::default(),
		server_pubkey: None,
	}
}

fn test_pubkey() -> bitcoin::secp256k1::PublicKey {
	let secp = Secp256k1::new();
	let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
	Keypair::from_secret_key(&secp, &sk).public_key()
}

// A known-valid BOLT11 invoice on signet (from test data in payment_method.rs)
const TEST_INVOICE_STR: &str = "lntbs100u1p5j0x82sp5d0rwfh7tgrrlwsegy9rx3tzpt36cqwjqza5x4wvcjxjzscfaf6jspp5d8q7354dg3p8h0kywhqq5dq984r8f5en98hf9ln85ug0w8fx6hhsdqqcqzpc9qyysgqyk54v7tpzprxll7e0jyvtxcpgwttzk84wqsfjsqvcdtq47zt2wssxsmtjhz8dka62mdnf9jafhu3l4cpyfnsx449v4wstrwzzql2w5qqs8uh7p";

fn test_bolt11() -> Bolt11Invoice {
	Bolt11Invoice::from_str(TEST_INVOICE_STR).expect("valid test invoice")
}

fn test_invoice() -> Invoice {
	Invoice::Bolt11(test_bolt11())
}

fn test_payment_hash() -> PaymentHash {
	test_invoice().payment_hash()
}

// A separate hash for receive tests so send and receive don't share state.
fn test_receive_payment_hash() -> PaymentHash {
	PaymentHash::from_slice(&[0xabu8; 32]).unwrap()
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

/// A second distinct transaction to avoid UNIQUE constraint collisions.
fn empty_tx_2() -> Transaction {
	Transaction {
		version: bitcoin::transaction::Version::ONE,
		lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
		input: vec![],
		output: vec![],
	}
}

/// Returns `now` truncated to millisecond precision.
///
/// SQLite stores timestamps as `%Y-%m-%d %H:%M:%f` (millisecond precision).
/// The memory backend stores nanoseconds.  Using a pre-truncated value ensures
/// both backends round-trip identically so `assert_eq!` on timestamps holds.
fn test_time() -> chrono::DateTime<chrono::Local> {
	let ms = chrono::Local::now().timestamp_millis();
	chrono::DateTime::from_timestamp_millis(ms)
		.unwrap()
		.with_timezone(&chrono::Local)
}

// ---------------------------------------------------------------------------
// Round state comparison helper
// ---------------------------------------------------------------------------

/// Compare two `StoredRoundState<Unlocked>` values for equality.
///
/// `RoundState` does not derive `PartialEq` or `Serialize` because
/// `RoundFlowState` contains `Keypair` and `DangerousSecretNonce`.  We compare
/// the fields that are observable in tests and that backends actually store.
fn round_states_match(a: &StoredRoundState<Unlocked>, b: &StoredRoundState<Unlocked>) -> bool {
	if a.id() != b.id() {
		return false;
	}
	let a_json = serde_json::to_string(&SerdeRoundState::from(a.state()))
		.expect("SerdeRoundState serialization failed for a");
	let b_json = serde_json::to_string(&SerdeRoundState::from(b.state()))
		.expect("SerdeRoundState serialization failed for b");
	a_json == b_json
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run all [BarkPersister] differential tests against `a` and `b`.
///
/// Both persisters must be freshly initialised (empty).  Every method is
/// called on both with identical inputs and the outputs are asserted equal,
/// so any behavioural divergence between the two backends surfaces as a test
/// failure.
pub async fn run_all<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
	wallet_properties::run(a, b).await;
	vtxo_keys::run(a, b).await;
	vtxo_lifecycle::run(a, b).await;
	movements::run(a, b).await;
	pending_boards::run(a, b).await;
	round_states::run(a, b).await;
	lightning::run(a, b).await;
}

// ---------------------------------------------------------------------------
// Group: wallet properties
// ---------------------------------------------------------------------------

mod wallet_properties {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_init_and_read_properties(a, b).await;
		test_set_server_pubkey(a, b).await;
	}

	async fn test_init_and_read_properties<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let props = test_properties();

		let ra = a.init_wallet(&props).await;
		let rb = b.init_wallet(&props).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "init_wallet: ok/err mismatch");

		let ra = a.read_properties().await.expect("a: read_properties");
		let rb = b.read_properties().await.expect("b: read_properties");
		assert_eq!(ra, rb, "read_properties mismatch");
	}

	async fn test_set_server_pubkey<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let pk = test_pubkey();

		let ra = a.set_server_pubkey(pk).await;
		let rb = b.set_server_pubkey(pk).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "set_server_pubkey: ok/err mismatch");

		let ra = a.read_properties().await.expect("a: read_properties after set_server_pubkey");
		let rb = b.read_properties().await.expect("b: read_properties after set_server_pubkey");
		assert_eq!(ra, rb, "read_properties after set_server_pubkey mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: VTXO keys and mailbox checkpoint
// ---------------------------------------------------------------------------

mod vtxo_keys {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_mailbox_checkpoint_empty_db(a, b).await;
		test_vtxo_keys_empty(a, b).await;
		test_vtxo_key_roundtrip(a, b).await;
		test_vtxo_key_last_index_advances(a, b).await;
		test_mailbox_checkpoint_roundtrip(a, b).await;
	}

	async fn test_mailbox_checkpoint_empty_db<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let ra = a.get_mailbox_checkpoint().await.expect("a: get_mailbox_checkpoint (empty)");
		let rb = b.get_mailbox_checkpoint().await.expect("b: get_mailbox_checkpoint (empty)");
		assert_eq!(ra, rb, "get_mailbox_checkpoint (empty db) mismatch");
		assert_eq!(ra, 0, "get_mailbox_checkpoint (empty db) should be 0");
	}

	async fn test_vtxo_keys_empty<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let pk = test_pubkey();

		let ra = a.get_last_vtxo_key_index().await.expect("a: get_last_vtxo_key_index");
		let rb = b.get_last_vtxo_key_index().await.expect("b: get_last_vtxo_key_index");
		assert_eq!(ra, rb, "get_last_vtxo_key_index (empty) mismatch");

		let ra = a.get_public_key_idx(&pk).await.expect("a: get_public_key_idx");
		let rb = b.get_public_key_idx(&pk).await.expect("b: get_public_key_idx");
		assert_eq!(ra, rb, "get_public_key_idx (empty) mismatch");
	}

	async fn test_vtxo_key_roundtrip<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let pk = test_pubkey();

		let ra = a.store_vtxo_key(0, pk).await;
		let rb = b.store_vtxo_key(0, pk).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_vtxo_key: ok/err mismatch");

		let ra = a.get_last_vtxo_key_index().await.expect("a: get_last_vtxo_key_index");
		let rb = b.get_last_vtxo_key_index().await.expect("b: get_last_vtxo_key_index");
		assert_eq!(ra, rb, "get_last_vtxo_key_index after store mismatch");

		let ra = a.get_public_key_idx(&pk).await.expect("a: get_public_key_idx");
		let rb = b.get_public_key_idx(&pk).await.expect("b: get_public_key_idx");
		assert_eq!(ra, rb, "get_public_key_idx after store mismatch");
	}

	async fn test_vtxo_key_last_index_advances<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let secp = Secp256k1::new();
		// store keys at indices 1 and 2 (0 already stored above)
		for i in 1u32..=2 {
			let sk = SecretKey::from_slice(&[i as u8 + 10; 32]).unwrap();
			let pk = Keypair::from_secret_key(&secp, &sk).public_key();

			let ra = a.store_vtxo_key(i, pk).await;
			let rb = b.store_vtxo_key(i, pk).await;
			assert_eq!(ra.is_ok(), rb.is_ok(), "store_vtxo_key {i}: ok/err mismatch");
		}

		let ra = a.get_last_vtxo_key_index().await.expect("a: get_last_vtxo_key_index");
		let rb = b.get_last_vtxo_key_index().await.expect("b: get_last_vtxo_key_index");
		assert_eq!(ra, rb, "get_last_vtxo_key_index after advance mismatch");
	}

	async fn test_mailbox_checkpoint_roundtrip<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let ra = a.store_mailbox_checkpoint(42).await;
		let rb = b.store_mailbox_checkpoint(42).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_mailbox_checkpoint: ok/err mismatch");

		let ra = a.get_mailbox_checkpoint().await.expect("a: get_mailbox_checkpoint");
		let rb = b.get_mailbox_checkpoint().await.expect("b: get_mailbox_checkpoint");
		assert_eq!(ra, rb, "get_mailbox_checkpoint mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: VTXO lifecycle
// ---------------------------------------------------------------------------

mod vtxo_lifecycle {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_store_and_get_vtxo(a, b).await;
		test_get_vtxos_by_state(a, b).await;
		test_vtxo_state_transition_ok(a, b).await;
		test_vtxo_state_transition_rejected(a, b).await;
		test_remove_vtxo(a, b).await;
		test_has_spent_vtxo(a, b).await;
		test_store_vtxos_idempotent(a, b).await;
	}

	async fn test_store_and_get_vtxo<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.board_vtxo;

		let ra = a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await;
		let rb = b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_vtxos: ok/err mismatch");

		let ra = a.get_wallet_vtxo(vtxo.id()).await.expect("a: get_wallet_vtxo");
		let rb = b.get_wallet_vtxo(vtxo.id()).await.expect("b: get_wallet_vtxo");
		assert_eq!(ra, rb, "get_wallet_vtxo mismatch");

		let mut ra = a.get_all_vtxos().await.expect("a: get_all_vtxos");
		let mut rb = b.get_all_vtxos().await.expect("b: get_all_vtxos");
		ra.sort_by_key(|v| v.vtxo.id());
		rb.sort_by_key(|v| v.vtxo.id());
		assert_eq!(ra, rb, "get_all_vtxos mismatch");
	}

	async fn test_get_vtxos_by_state<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let spendable = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let spent = &VTXO_VECTORS.arkoor2_vtxo;

		let ra = a.store_vtxos(&[
			(spendable, &VtxoState::Spendable),
			(spent, &VtxoState::Spent),
		]).await;
		let rb = b.store_vtxos(&[
			(spendable, &VtxoState::Spendable),
			(spent, &VtxoState::Spent),
		]).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_vtxos: ok/err mismatch");

		let mut ra = a.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await
			.expect("a: get_vtxos_by_state");
		let mut rb = b.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await
			.expect("b: get_vtxos_by_state");
		ra.sort_by_key(|v| v.vtxo.id());
		rb.sort_by_key(|v| v.vtxo.id());
		assert_eq!(ra, rb, "get_vtxos_by_state mismatch");
	}

	async fn test_vtxo_state_transition_ok<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.round1_vtxo;

		a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("a: store_vtxos");
		b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("b: store_vtxos");

		let ra = a.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, VtxoStateKind::UNSPENT_STATES).await;
		let rb = b.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, VtxoStateKind::UNSPENT_STATES).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "update_vtxo_state_checked: ok/err mismatch");
		assert_eq!(ra.unwrap(), rb.unwrap(), "update_vtxo_state_checked result mismatch");
	}

	async fn test_vtxo_state_transition_rejected<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.round2_vtxo;

		a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("a: store_vtxos");
		b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("b: store_vtxos");

		let ra = a.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Spent]).await;
		let rb = b.update_vtxo_state_checked(vtxo.id(), VtxoState::Spent, &[VtxoStateKind::Spent]).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "update_vtxo_state_checked (rejected): ok/err mismatch");
		assert!(ra.is_err(), "transition from Spendable with only Spent allowed should be rejected");
	}

	async fn test_remove_vtxo<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;

		a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("a: store_vtxos");
		b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("b: store_vtxos");

		let ra = a.remove_vtxo(vtxo.id()).await.expect("a: remove_vtxo");
		let rb = b.remove_vtxo(vtxo.id()).await.expect("b: remove_vtxo");
		assert_eq!(ra, rb, "remove_vtxo result mismatch");

		let ra = a.get_wallet_vtxo(vtxo.id()).await.expect("a: get_wallet_vtxo after remove");
		let rb = b.get_wallet_vtxo(vtxo.id()).await.expect("b: get_wallet_vtxo after remove");
		assert_eq!(ra, rb, "get_wallet_vtxo after remove mismatch");
	}

	async fn test_has_spent_vtxo<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let spent = &VTXO_VECTORS.arkoor2_vtxo;

		// Ensure the vtxo is in Spent state before querying.  store_vtxos uses
		// INSERT OR IGNORE semantics, so this is a no-op if the vtxo was already
		// stored by an earlier test.
		a.store_vtxos(&[(spent, &VtxoState::Spent)]).await.expect("a: store_vtxos");
		b.store_vtxos(&[(spent, &VtxoState::Spent)]).await.expect("b: store_vtxos");

		let ra = a.has_spent_vtxo(spent.id()).await.expect("a: has_spent_vtxo");
		let rb = b.has_spent_vtxo(spent.id()).await.expect("b: has_spent_vtxo");
		assert_eq!(ra, rb, "has_spent_vtxo mismatch");

		let unknown_id = VtxoId::from_slice(&[0u8; 36]).unwrap();
		let ra = a.has_spent_vtxo(unknown_id).await.expect("a: has_spent_vtxo (unknown)");
		let rb = b.has_spent_vtxo(unknown_id).await.expect("b: has_spent_vtxo (unknown)");
		assert_eq!(ra, rb, "has_spent_vtxo (unknown) mismatch");
	}

	async fn test_store_vtxos_idempotent<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.board_vtxo;

		// First store — ensures the vtxo exists regardless of prior test state.
		a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("a: initial store_vtxos");
		b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("b: initial store_vtxos");

		// Second store with the same state — this is the idempotency check.
		let ra = a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await;
		let rb = b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_vtxos (idempotent): ok/err mismatch");

		let ra = a.get_wallet_vtxo(vtxo.id()).await.expect("a: get_wallet_vtxo after idempotent store");
		let rb = b.get_wallet_vtxo(vtxo.id()).await.expect("b: get_wallet_vtxo after idempotent store");
		assert_eq!(ra, rb, "get_wallet_vtxo after idempotent store mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: movements
// ---------------------------------------------------------------------------

mod movements {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_create_and_get_movement(a, b).await;
		test_update_movement(a, b).await;
		test_get_all_movements(a, b).await;
	}

	async fn test_create_and_get_movement<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let subsystem = test_subsystem();
		let time = test_time();

		let id_a = a.create_new_movement(MovementStatus::Pending, &subsystem, time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &subsystem, time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		let ra = a.get_movement_by_id(id_a).await.expect("a: get_movement_by_id");
		let rb = b.get_movement_by_id(id_b).await.expect("b: get_movement_by_id");
		assert_eq!(ra, rb, "get_movement_by_id mismatch");
	}

	async fn test_update_movement<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let time = test_time();
		let id_a = a.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		let mut movement_a = a.get_movement_by_id(id_a).await.expect("a: get_movement_by_id");
		let mut movement_b = b.get_movement_by_id(id_b).await.expect("b: get_movement_by_id");
		movement_a.status = MovementStatus::Successful;
		movement_a.intended_balance = bitcoin::SignedAmount::from_sat(1000);
		movement_b.status = MovementStatus::Successful;
		movement_b.intended_balance = bitcoin::SignedAmount::from_sat(1000);

		let ra = a.update_movement(&movement_a).await;
		let rb = b.update_movement(&movement_b).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "update_movement: ok/err mismatch");

		let ra = a.get_movement_by_id(id_a).await.expect("a: get_movement_by_id after update");
		let rb = b.get_movement_by_id(id_b).await.expect("b: get_movement_by_id after update");
		assert_eq!(ra, rb, "get_movement_by_id after update mismatch");
	}

	async fn test_get_all_movements<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let subsystem = test_subsystem();
		let time = test_time();

		a.create_new_movement(MovementStatus::Pending, &subsystem, time).await
			.expect("a: create_new_movement 1");
		b.create_new_movement(MovementStatus::Pending, &subsystem, time).await
			.expect("b: create_new_movement 1");
		a.create_new_movement(MovementStatus::Failed, &subsystem, time).await
			.expect("a: create_new_movement 2");
		b.create_new_movement(MovementStatus::Failed, &subsystem, time).await
			.expect("b: create_new_movement 2");

		let mut ra = a.get_all_movements().await.expect("a: get_all_movements");
		let mut rb = b.get_all_movements().await.expect("b: get_all_movements");
		ra.sort_by_key(|m| m.id.0);
		rb.sort_by_key(|m| m.id.0);
		assert_eq!(ra, rb, "get_all_movements mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: pending boards
// ---------------------------------------------------------------------------

mod pending_boards {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_store_and_get_pending_board(a, b).await;
		test_get_all_pending_board_ids(a, b).await;
		test_remove_pending_board(a, b).await;
	}

	async fn test_store_and_get_pending_board<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.board_vtxo;
		let funding_tx = empty_tx();
		let time = test_time();

		let id_a = a.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		let ra = a.store_pending_board(vtxo, &funding_tx, id_a).await;
		let rb = b.store_pending_board(vtxo, &funding_tx, id_b).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_pending_board: ok/err mismatch");

		let ra = a.get_pending_board_by_vtxo_id(vtxo.id()).await
			.expect("a: get_pending_board_by_vtxo_id");
		let rb = b.get_pending_board_by_vtxo_id(vtxo.id()).await
			.expect("b: get_pending_board_by_vtxo_id");
		assert_eq!(ra, rb, "get_pending_board_by_vtxo_id mismatch");
	}

	async fn test_get_all_pending_board_ids<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo2 = &VTXO_VECTORS.round2_vtxo;
		let time = test_time();

		let id_a = a.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		a.store_pending_board(vtxo2, &empty_tx_2(), id_a).await.expect("a: store_pending_board");
		b.store_pending_board(vtxo2, &empty_tx_2(), id_b).await.expect("b: store_pending_board");

		let mut ra = a.get_all_pending_board_ids().await.expect("a: get_all_pending_board_ids");
		let mut rb = b.get_all_pending_board_ids().await.expect("b: get_all_pending_board_ids");
		ra.sort();
		rb.sort();
		assert_eq!(ra, rb, "get_all_pending_board_ids mismatch");
	}

	async fn test_remove_pending_board<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let vtxo = &VTXO_VECTORS.board_vtxo;

		let ra = a.remove_pending_board(&vtxo.id()).await;
		let rb = b.remove_pending_board(&vtxo.id()).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "remove_pending_board: ok/err mismatch");

		let ra = a.get_pending_board_by_vtxo_id(vtxo.id()).await
			.expect("a: get_pending_board_by_vtxo_id after removal");
		let rb = b.get_pending_board_by_vtxo_id(vtxo.id()).await
			.expect("b: get_pending_board_by_vtxo_id after removal");
		assert_eq!(ra, rb, "get_pending_board_by_vtxo_id after removal mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: round states
// ---------------------------------------------------------------------------

mod round_states {
	use super::*;

	fn empty_round_state() -> RoundState {
		RoundState {
			done: false,
			participation: RoundParticipation { inputs: vec![], outputs: vec![] },
			flow: RoundFlowState::InteractivePending,
			new_vtxos: vec![],
			sent_forfeit_sigs: false,
			movement_id: None,
		}
	}

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_store_and_get_round_state(a, b).await;
		test_store_round_state_with_vtxo_locking(a, b).await;
		test_update_round_state(a, b).await;
		test_remove_round_state(a, b).await;
	}

	async fn test_store_round_state_with_vtxo_locking<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		// arkoor3_vtxo was removed by vtxo_lifecycle::test_remove_vtxo, so it is
		// absent from both backends.  Re-inserting it gives us a fresh Spendable
		// vtxo to use as round input, which exercises the locking loop inside
		// store_round_state_lock_vtxos.
		let vtxo = &VTXO_VECTORS.arkoor3_vtxo;

		a.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("a: store_vtxos for locking test");
		b.store_vtxos(&[(vtxo, &VtxoState::Spendable)]).await.expect("b: store_vtxos for locking test");

		let state = RoundState {
			done: false,
			participation: RoundParticipation { inputs: vec![vtxo.as_ref().clone()], outputs: vec![] },
			flow: RoundFlowState::InteractivePending,
			new_vtxos: vec![],
			sent_forfeit_sigs: false,
			movement_id: None,
		};

		let id_a = a.store_round_state_lock_vtxos(&state).await.expect("a: store_round_state_lock_vtxos");
		let id_b = b.store_round_state_lock_vtxos(&state).await.expect("b: store_round_state_lock_vtxos");
		assert_eq!(id_a, id_b, "store_round_state_lock_vtxos id mismatch");

		// Both backends must have transitioned the vtxo to Locked.
		let ra = a.get_wallet_vtxo(vtxo.id()).await.expect("a: get_wallet_vtxo after lock");
		let rb = b.get_wallet_vtxo(vtxo.id()).await.expect("b: get_wallet_vtxo after lock");
		assert_eq!(ra, rb, "get_wallet_vtxo after lock mismatch");
		assert!(
			matches!(ra.as_ref().map(|w| &w.state), Some(VtxoState::Locked { .. })),
			"vtxo should be Locked after store_round_state_lock_vtxos",
		);
	}

	async fn test_store_and_get_round_state<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let state = empty_round_state();

		let id_a = a.store_round_state_lock_vtxos(&state).await.expect("a: store_round_state");
		let id_b = b.store_round_state_lock_vtxos(&state).await.expect("b: store_round_state");
		assert_eq!(id_a, id_b, "store_round_state id mismatch");

		let mut ra = a.get_pending_round_state_ids().await.expect("a: get_pending_round_state_ids");
		let mut rb = b.get_pending_round_state_ids().await.expect("b: get_pending_round_state_ids");
		ra.sort_by_key(|id| id.0);
		rb.sort_by_key(|id| id.0);
		assert_eq!(ra, rb, "get_pending_round_state_ids mismatch");

		let ra = a.get_round_state_by_id(id_a).await.expect("a: get_round_state_by_id");
		let rb = b.get_round_state_by_id(id_b).await.expect("b: get_round_state_by_id");
		assert_eq!(ra.is_some(), rb.is_some(), "get_round_state_by_id: presence mismatch");
		assert!(
			round_states_match(ra.as_ref().unwrap(), rb.as_ref().unwrap()),
			"get_round_state_by_id: content mismatch",
		);
	}

	async fn test_update_round_state<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		// Each backend gets its own lock index: id_a == id_b numerically but
		// they guard different backends, so they must not share a lock index.
		let lock_index_a = RoundStateLockIndex::new();
		let lock_index_b = RoundStateLockIndex::new();

		let id_a = a.store_round_state_lock_vtxos(&empty_round_state()).await.expect("a: store_round_state");
		let id_b = b.store_round_state_lock_vtxos(&empty_round_state()).await.expect("b: store_round_state");
		assert_eq!(id_a, id_b, "store_round_state id mismatch");

		let unlocked_a = a.get_round_state_by_id(id_a).await.expect("a: get_round_state_by_id").unwrap();
		let unlocked_b = b.get_round_state_by_id(id_b).await.expect("b: get_round_state_by_id").unwrap();

		let guard_a = lock_index_a.try_lock(id_a).expect("a: lock should succeed");
		let guard_b = lock_index_b.try_lock(id_b).expect("b: lock should succeed");
		let mut stored_a = unlocked_a.lock(guard_a);
		let mut stored_b = unlocked_b.lock(guard_b);
		stored_a.state_mut().done = true;
		stored_b.state_mut().done = true;

		let ra = a.update_round_state(&stored_a).await;
		let rb = b.update_round_state(&stored_b).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "update_round_state: ok/err mismatch");

		let ra = a.get_round_state_by_id(id_a).await.expect("a: get_round_state_by_id after update");
		let rb = b.get_round_state_by_id(id_b).await.expect("b: get_round_state_by_id after update");
		assert_eq!(ra.is_some(), rb.is_some(), "get_round_state_by_id: presence mismatch after update");
		assert!(
			round_states_match(ra.as_ref().unwrap(), rb.as_ref().unwrap()),
			"get_round_state_by_id: content mismatch after update",
		);
	}

	async fn test_remove_round_state<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let lock_index_a = RoundStateLockIndex::new();
		let lock_index_b = RoundStateLockIndex::new();

		let id_a = a.store_round_state_lock_vtxos(&empty_round_state()).await.expect("a: store_round_state");
		let id_b = b.store_round_state_lock_vtxos(&empty_round_state()).await.expect("b: store_round_state");
		assert_eq!(id_a, id_b, "store_round_state id mismatch");

		let unlocked_a = a.get_round_state_by_id(id_a).await.expect("a: get_round_state_by_id").unwrap();
		let unlocked_b = b.get_round_state_by_id(id_b).await.expect("b: get_round_state_by_id").unwrap();

		let guard_a = lock_index_a.try_lock(id_a).expect("a: lock should succeed");
		let guard_b = lock_index_b.try_lock(id_b).expect("b: lock should succeed");
		let stored_a = unlocked_a.lock(guard_a);
		let stored_b = unlocked_b.lock(guard_b);

		let ra = a.remove_round_state(&stored_a).await;
		let rb = b.remove_round_state(&stored_b).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "remove_round_state: ok/err mismatch");

		let ra = a.get_round_state_by_id(id_a).await.expect("a: get_round_state_by_id after remove");
		let rb = b.get_round_state_by_id(id_b).await.expect("b: get_round_state_by_id after remove");
		assert!(ra.is_none() && rb.is_none(), "get_round_state_by_id should be None after remove");

		let mut ra = a.get_pending_round_state_ids().await
			.expect("a: get_pending_round_state_ids after remove");
		let mut rb = b.get_pending_round_state_ids().await
			.expect("b: get_pending_round_state_ids after remove");
		ra.sort_by_key(|id| id.0);
		rb.sort_by_key(|id| id.0);
		assert_eq!(ra, rb, "get_pending_round_state_ids after remove mismatch");
	}
}

// ---------------------------------------------------------------------------
// Group: lightning
// ---------------------------------------------------------------------------

mod lightning {
	use super::*;

	pub async fn run<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		test_lightning_send_store_and_query(a, b).await;
		test_lightning_send_finish(a, b).await;
		test_lightning_send_remove(a, b).await;
		test_lightning_receive_store_and_query(a, b).await;
		test_lightning_receive_set_preimage_revealed(a, b).await;
		test_lightning_receive_update(a, b).await;
		test_lightning_receive_finish(a, b).await;
	}

	async fn test_lightning_send_store_and_query<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let time = test_time();
		let id_a = a.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		let ra = a.store_new_pending_lightning_send(
			&test_invoice(), Amount::from_sat(1000), Amount::from_sat(10), &[], id_a,
		).await;
		let rb = b.store_new_pending_lightning_send(
			&test_invoice(), Amount::from_sat(1000), Amount::from_sat(10), &[], id_b,
		).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_new_pending_lightning_send: ok/err mismatch");
		assert_eq!(ra.unwrap(), rb.unwrap(), "store_new_pending_lightning_send result mismatch");

		let ra = a.get_lightning_send(test_payment_hash()).await.expect("a: get_lightning_send");
		let rb = b.get_lightning_send(test_payment_hash()).await.expect("b: get_lightning_send");
		assert_eq!(ra, rb, "get_lightning_send mismatch");

		let mut ra = a.get_all_pending_lightning_send().await.expect("a: get_all_pending_lightning_send");
		let mut rb = b.get_all_pending_lightning_send().await.expect("b: get_all_pending_lightning_send");
		ra.sort_by_key(|s| s.movement_id.0);
		rb.sort_by_key(|s| s.movement_id.0);
		assert_eq!(ra, rb, "get_all_pending_lightning_send mismatch");
	}

	async fn test_lightning_send_finish<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_payment_hash();
		let preimage = test_preimage();

		let ra = a.finish_lightning_send(hash, Some(preimage)).await;
		let rb = b.finish_lightning_send(hash, Some(preimage)).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "finish_lightning_send: ok/err mismatch");

		// finished_at is set internally by each backend; compare only semantic fields
		let ra = a.get_lightning_send(hash).await.expect("a: get_lightning_send after finish");
		let rb = b.get_lightning_send(hash).await.expect("b: get_lightning_send after finish");
		assert_eq!(
			ra.as_ref().map(|s| s.preimage),
			rb.as_ref().map(|s| s.preimage),
			"get_lightning_send preimage mismatch after finish",
		);
		assert_eq!(
			ra.as_ref().map(|s| s.finished_at.is_some()),
			rb.as_ref().map(|s| s.finished_at.is_some()),
			"get_lightning_send finished_at presence mismatch after finish",
		);

		let mut ra = a.get_all_pending_lightning_send().await
			.expect("a: get_all_pending_lightning_send after finish");
		let mut rb = b.get_all_pending_lightning_send().await
			.expect("b: get_all_pending_lightning_send after finish");
		ra.sort_by_key(|s| s.movement_id.0);
		rb.sort_by_key(|s| s.movement_id.0);
		assert_eq!(ra, rb, "get_all_pending_lightning_send after finish mismatch");
	}

	async fn test_lightning_send_remove<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_payment_hash();

		let ra = a.remove_lightning_send(hash).await;
		let rb = b.remove_lightning_send(hash).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "remove_lightning_send: ok/err mismatch");

		let ra = a.get_lightning_send(hash).await.expect("a: get_lightning_send after remove");
		let rb = b.get_lightning_send(hash).await.expect("b: get_lightning_send after remove");
		assert_eq!(ra, rb, "get_lightning_send after remove mismatch");
	}

	async fn test_lightning_receive_store_and_query<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_receive_payment_hash();
		let preimage = test_preimage();

		let ra = a.store_lightning_receive(hash, preimage, &test_bolt11(), 40).await;
		let rb = b.store_lightning_receive(hash, preimage, &test_bolt11(), 40).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "store_lightning_receive: ok/err mismatch");

		let ra = a.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("a: fetch_lightning_receive_by_payment_hash");
		let rb = b.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("b: fetch_lightning_receive_by_payment_hash");
		assert_eq!(ra, rb, "fetch_lightning_receive_by_payment_hash mismatch");

		let mut ra = a.get_all_pending_lightning_receives().await
			.expect("a: get_all_pending_lightning_receives");
		let mut rb = b.get_all_pending_lightning_receives().await
			.expect("b: get_all_pending_lightning_receives");
		ra.sort_by_key(|r| r.payment_hash);
		rb.sort_by_key(|r| r.payment_hash);
		assert_eq!(ra, rb, "get_all_pending_lightning_receives mismatch");
	}

	async fn test_lightning_receive_set_preimage_revealed<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_receive_payment_hash();

		let ra = a.set_preimage_revealed(hash).await;
		let rb = b.set_preimage_revealed(hash).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "set_preimage_revealed: ok/err mismatch");

		// preimage_revealed_at is set internally; compare presence only
		let ra = a.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("a: fetch after set_preimage_revealed");
		let rb = b.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("b: fetch after set_preimage_revealed");
		assert_eq!(
			ra.as_ref().map(|r| r.preimage_revealed_at.is_some()),
			rb.as_ref().map(|r| r.preimage_revealed_at.is_some()),
			"preimage_revealed_at presence mismatch",
		);
	}

	async fn test_lightning_receive_update<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_receive_payment_hash();
		let vtxo = &VTXO_VECTORS.round2_vtxo;
		let time = test_time();

		let id_a = a.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("a: create_new_movement");
		let id_b = b.create_new_movement(MovementStatus::Pending, &test_subsystem(), time).await
			.expect("b: create_new_movement");
		assert_eq!(id_a, id_b, "create_new_movement id mismatch");

		let ra = a.update_lightning_receive(hash, &[vtxo.id()], id_a).await;
		let rb = b.update_lightning_receive(hash, &[vtxo.id()], id_b).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "update_lightning_receive: ok/err mismatch");

		let ra = a.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("a: fetch after update_lightning_receive");
		let rb = b.fetch_lightning_receive_by_payment_hash(hash).await
			.expect("b: fetch after update_lightning_receive");
		assert_eq!(
			ra.as_ref().map(|r| r.movement_id),
			rb.as_ref().map(|r| r.movement_id),
			"movement_id mismatch after update_lightning_receive",
		);
	}

	async fn test_lightning_receive_finish<A: BarkPersister, B: BarkPersister>(a: &A, b: &B) {
		let hash = test_receive_payment_hash();

		let ra = a.finish_pending_lightning_receive(hash).await;
		let rb = b.finish_pending_lightning_receive(hash).await;
		assert_eq!(ra.is_ok(), rb.is_ok(), "finish_pending_lightning_receive: ok/err mismatch");

		let mut ra = a.get_all_pending_lightning_receives().await
			.expect("a: get_all_pending_lightning_receives after finish");
		let mut rb = b.get_all_pending_lightning_receives().await
			.expect("b: get_all_pending_lightning_receives after finish");
		ra.sort_by_key(|r| r.payment_hash);
		rb.sort_by_key(|r| r.payment_hash);
		assert_eq!(ra, rb, "get_all_pending_lightning_receives after finish mismatch");
	}
}
