use ark_testing::{TestContext, btc};

use bark::movement::MovementId;
use bark::vtxo::{VtxoLockHolder, VtxoState};

/// Every vtxo lock is owned by exactly one holder; a second holder
/// must not be able to take it over via [bark::Wallet::lock_vtxos].
#[ignore = "repro: lock_vtxos currently no-ops when re-locking a Locked vtxo, silently letting holder2 take over"]
#[tokio::test]
async fn locks_cannot_be_stolen() {
	let ctx = TestContext::new("bark_sdk/locks_cannot_be_stolen").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(btc(1))
		.create().await;

	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	let holder1 = VtxoLockHolder::Movement { id: MovementId::new(1) };
	wallet.lock_vtxos(vec![vtxo_id], Some(holder1.clone())).await
		.expect("first lock on a spendable vtxo should succeed");

	// Re-locking with the same holder must stay idempotent.
	wallet.lock_vtxos(vec![vtxo_id], Some(holder1.clone())).await
		.expect("re-locking with the same holder should be idempotent");

	let holder2 = VtxoLockHolder::Movement { id: MovementId::new(2) };
	wallet.lock_vtxos(vec![vtxo_id], Some(holder2)).await
		.expect_err("a second holder must not be able to steal an existing lock");

	let [after] = wallet.vtxos().await.expect("list vtxos after failed lock")
		.try_into().expect("expected exactly one vtxo");
	match after.state {
		VtxoState::Locked { holder: Some(h) } => assert_eq!(h, holder1),
		other => panic!("vtxo should still be locked by holder 1, was {:?}", other),
	}
}
