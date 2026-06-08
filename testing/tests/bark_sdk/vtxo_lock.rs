use ark::VtxoId;

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

/// Batch lock must be all-or-nothing: if any vtxo in the batch is
/// already locked by another holder, the whole call fails and no
/// vtxo in the batch changes state.
#[ignore = "repro: set_vtxo_states loops per-vtxo and partially locks the batch before failing on the overlap"]
#[tokio::test]
async fn batch_lock_is_atomic() {
	let ctx = TestContext::new("bark_sdk/batch_lock_is_atomic").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(btc(1))
		.boarded(btc(1))
		.boarded(btc(1))
		.create().await;

	let [a, b, c]: [VtxoId; 3] = wallet.vtxos().await.expect("list vtxos")
		.iter().map(|v| v.vtxo.id()).collect::<Vec<_>>()
		.try_into().expect("expected exactly three boarded vtxos");

	let holder1 = VtxoLockHolder::Movement { id: MovementId::new(1) };
	wallet.lock_vtxos(vec![a, b], Some(holder1.clone())).await
		.expect("first batch lock on spendable vtxos should succeed");

	// holder2 overlaps with holder1 on `b`, so the whole batch must
	// be rejected — `c` must stay untouched.
	let holder2 = VtxoLockHolder::Movement { id: MovementId::new(2) };
	wallet.lock_vtxos(vec![b, c], Some(holder2)).await
		.expect_err("overlapping batch lock must fail atomically");

	let a_state = wallet.get_vtxo_by_id(a).await.expect("get vtxo a").state;
	let b_state = wallet.get_vtxo_by_id(b).await.expect("get vtxo b").state;
	let c_state = wallet.get_vtxo_by_id(c).await.expect("get vtxo c").state;

	assert!(
		matches!(&a_state, VtxoState::Locked { holder: Some(h) } if *h == holder1),
		"vtxo a should still be locked by holder 1, was {:?}", a_state,
	);
	assert!(
		matches!(&b_state, VtxoState::Locked { holder: Some(h) } if *h == holder1),
		"vtxo b should still be locked by holder 1, was {:?}", b_state,
	);
	assert!(
		matches!(c_state, VtxoState::Spendable),
		"vtxo c should be untouched by the failed batch, was {:?}", c_state,
	);
}

#[tokio::test]
async fn unlock_returns_vtxo_to_spendable() {
	let ctx = TestContext::new("bark_sdk/unlock_returns_vtxo_to_spendable").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(btc(1))
		.create().await;

	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	let holder = VtxoLockHolder::Movement { id: MovementId::new(1) };
	wallet.lock_vtxos(vec![vtxo_id], Some(holder)).await
		.expect("lock should succeed");

	wallet.unlock_vtxos(vec![vtxo_id]).await
		.expect("unlock should succeed");

	let state = wallet.get_vtxo_by_id(vtxo_id).await.expect("get vtxo").state;
	assert!(
		matches!(state, VtxoState::Spendable),
		"unlocked vtxo should be Spendable, was {:?}", state,
	);
}

/// `lock_vtxos` rejects anything that isn't in an unspent state — a
/// Spent vtxo or an unknown id must not silently succeed.
#[tokio::test]
async fn can_only_lock_spendable_vtxo() {
	let ctx = TestContext::new("bark_sdk/can_only_lock_spendable_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(btc(1))
		.create().await;

	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let spent_id = vtxo.vtxo.id();

	wallet.mark_vtxos_as_spent(vec![spent_id]).await
		.expect("marking the vtxo as spent should succeed");

	let holder = VtxoLockHolder::Movement { id: MovementId::new(1) };

	wallet.lock_vtxos(vec![spent_id], Some(holder.clone())).await
		.expect_err("locking a spent vtxo should fail");

	let state = wallet.get_vtxo_by_id(spent_id).await.expect("get vtxo").state;
	assert!(
		matches!(state, VtxoState::Spent),
		"spent vtxo should remain Spent after the failed lock, was {:?}", state,
	);

	let missing_id = VtxoId::from_slice(&[0u8; VtxoId::ENCODE_SIZE]).unwrap();
	wallet.lock_vtxos(vec![missing_id], Some(holder)).await
		.expect_err("locking a non-existent vtxo should fail");
}

/// `unlock_vtxos` must reject Spent — unlocking a consumed vtxo back
/// to Spendable would let the wallet double-spend it.
#[tokio::test]
async fn cannot_unlock_spent_vtxo() {
	let ctx = TestContext::new("bark_sdk/cannot_unlock_spent_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let wallet = ctx.bark_sdk("bark", &srv)
		.boarded(btc(1))
		.create().await;

	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	wallet.mark_vtxos_as_spent(vec![vtxo_id]).await
		.expect("marking the vtxo as spent should succeed");

	wallet.unlock_vtxos(vec![vtxo_id]).await
		.expect_err("unlocking a spent vtxo should fail");

	let state = wallet.get_vtxo_by_id(vtxo_id).await.expect("get vtxo").state;
	assert!(
		matches!(state, VtxoState::Spent),
		"vtxo should remain Spent after the failed unlock, was {:?}", state,
	);
}
