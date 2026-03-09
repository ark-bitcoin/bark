//! Differential test suite for [BarkPersister] implementations.
//!
//! Call [run_all] with two freshly created persisters to verify that both
//! implementations satisfy the [BarkPersister] contract and produce identical
//! results for every operation.  Invoke this from a `#[tokio::test]` that
//! constructs one instance of each backend under test.

use bitcoin::bip32::Fingerprint;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::Network;

use super::BarkPersister;
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
