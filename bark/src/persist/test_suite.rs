//! Differential test suite for [BarkPersister] implementations.
//!
//! Call [run_all] with two freshly created persisters to verify that both
//! implementations satisfy the [BarkPersister] contract and produce identical
//! results for every operation.  Invoke this from a `#[tokio::test]` that
//! constructs one instance of each backend under test.

use bitcoin::bip32::Fingerprint;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::Network;

use ark::test_util::VTXO_VECTORS;
use ark::VtxoId;

use super::BarkPersister;
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
