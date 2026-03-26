use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;

use ark::lightning::Preimage;
use server::database::Db;
use server::ln::settler::HtlcSettler;
use server::system::RuntimeManager;

use ark_testing::TestContext;
use ark_testing::util::FutureExt;

/// Settle 50 preimages, subscribe with batch_size=10, and verify all
/// 50 arrive without relying on the background poller.
///
/// The poll interval is set absurdly high to prove the stream drains
/// purely through the "full batch → re-poll" path.
#[tokio::test]
async fn subscribe_drains_batches() {
	let mut ctx = TestContext::new_minimal("server/subscribe_drains_batches").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.unwrap();
	let db = Db::connect(&postgres_cfg).await.unwrap();

	let rtmgr = RuntimeManager::new();
	let mut settler = HtlcSettler::start(db, rtmgr, Duration::from_secs(9999));
	settler.batch_size(10);

	// Generate and settle 50 preimages.
	let preimages: Vec<Preimage> = (0..50).map(|_| Preimage::random()).collect();
	for p in &preimages {
		settler.settle(*p).await.unwrap();
	}

	// Subscribe from the beginning and drain all 50.
	let mut stream = Box::pin(settler.subscribe(0));
	let mut received = Vec::new();
	for _ in 0..50 {
		let s = stream.next().ready().await.unwrap();
		received.push(s);
	}

	// Verify we got every preimage (order matches insertion order).
	assert_eq!(received.len(), 50);
	for (settlement, expected) in received.iter().zip(&preimages) {
		assert_eq!(settlement.preimage, *expected);
		assert_eq!(settlement.hash, expected.compute_payment_hash());
	}
}

/// Two settler instances sharing one database, emulating the
/// captaind (reader) / watchmand (writer) split.
///
/// The writer settles preimages. The reader's subscribe stream picks
/// them up via its background poller — the writer's in-process notify
/// does not reach the reader.
#[tokio::test]
async fn cross_process_settlement() {
	let mut ctx = TestContext::new_minimal("server/cross_process_settlement").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.unwrap();
	let db = Db::connect(&postgres_cfg).await.unwrap();

	// Writer: poll interval irrelevant.
	let writer = HtlcSettler::start(db.clone(), RuntimeManager::new(), Duration::from_secs(9999));

	// Reader: short poll interval so it discovers cross-process writes.
	let reader = HtlcSettler::start(db, RuntimeManager::new(), Duration::from_millis(500));

	let mut stream = Box::pin(reader.subscribe(0));

	let preimages: Vec<Preimage> = (0..5).map(|_| Preimage::random()).collect();
	for p in &preimages {
		writer.settle(*p).await.unwrap();
	}

	for expected in &preimages {
		let s = stream.next().ready().await.unwrap();
		assert_eq!(s.preimage, *expected);
		assert_eq!(s.hash, expected.compute_payment_hash());
	}
}

/// 50 concurrent subscribers each reading from their own stream while
/// 50 preimages are settled from separate tasks — all running at the
/// same time via join_all.
///
/// This exercises the "notification while subscriber is busy reading a
/// batch" path that previously caused missed wake-ups.
#[tokio::test]
async fn concurrent_subscribers_no_missed_wakeups() {
	let mut ctx = TestContext::new_minimal("server/concurrent_subscribers_no_missed_wakeups").await;
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;

	Db::create(&postgres_cfg).await.unwrap();
	let db = Db::connect(&postgres_cfg).await.unwrap();

	let rtmgr = RuntimeManager::new();
	// No background poller — any missed wake-up will hang.
	let settler = HtlcSettler::start(db, rtmgr, Duration::from_secs(9999));
	let settler = Arc::new(settler);

	let n = 50;
	let preimages: Vec<Preimage> = (0..n).map(|_| Preimage::random()).collect();

	let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

	// Interleave reader and writer spawns so they race against each other.
	for p in &preimages {
		let mut stream = Box::pin(settler.subscribe(0));
		tasks.push(tokio::spawn(async move {
			for _ in 0..n {
				stream.next().ready().await.unwrap();
			}
		}));

		let settler = settler.clone();
		let preimage = *p;
		tasks.push(tokio::spawn(async move {
			settler.settle(preimage).await.unwrap();
		}));
	}

	futures::future::join_all(tasks).await
		.into_iter().collect::<Result<Vec<_>, _>>().unwrap();
}
