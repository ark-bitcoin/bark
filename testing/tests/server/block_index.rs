use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use anyhow::bail;
use bitcoin::{Address, BlockHash, address::NetworkUnchecked};


use bitcoin_ext::{BlockDelta, BlockHeight, BlockRef};
use bitcoin_ext::rpc::{BitcoinRpcExt, BitcoinRpcClient, RpcApi};

use server::sync::{ChainEventListener, RawMempool, BlockData};
use server::sync::block_index::{BlockIndex};
use server::database::{BlockTable, Db};

use ark_testing::TestContext;

/// Checks that the block index is fully consistent with the bitcoind chain
async fn check_block_index_is_consistent(db: &Db, block_table: BlockTable, bitcoind: &BitcoinRpcClient) {

	let lowest_block = db.read(async |t| t.get_lowest_block(block_table).await).await.unwrap().unwrap();
	let highest_block = db.read(async |t| t.get_highest_block(block_table).await).await.unwrap().unwrap();

	for height in lowest_block.height.to_u32()..=highest_block.height.to_u32() {
		let bitcoind_block = bitcoind.get_block_by_height(BlockHeight::new(height)).unwrap();
		let db_block = db.read(async |t| t.get_block_by_height(block_table, BlockHeight::new(height)).await).await.unwrap().unwrap();

		assert_eq!(bitcoind_block.hash, db_block.hash);
	}
}

pub struct BlockIndexListener {
	tip: parking_lot::Mutex<Option<BlockRef>>,
}

impl BlockIndexListener {
	pub fn new() -> Self {
		Self { tip: parking_lot::Mutex::new(None) }
	}
}

#[async_trait::async_trait]
impl ChainEventListener for BlockIndexListener {

	async fn on_mempool_update(&self, _raw: &RawMempool) -> anyhow::Result<()> {
		panic!("This should never be called")
	}


	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		let mut tip = self.tip.lock();
		match *tip {
			None => {
				*tip = Some(block.block_ref);
			},
			Some(prev) => {
				if block.block_ref.height == prev.height + BlockDelta::new(1) {
					*tip = Some(block.block_ref);
				} else if block.block_ref.height == prev.height && block.block_ref.hash == prev.hash {
					// Already at this tip, do nothing
				} else {
					panic!(
						"BlockIndexListener: unexpected block addition: prev tip = {:?}, new block = {:?}",
						prev, block.block_ref
					);
				}
			}
		}

		Ok(())
	}

	async fn on_reorg(&self, block: BlockRef) -> anyhow::Result<()> {
		if let Some(tip) = *self.tip.lock() {
			if block.height > tip.height {
				panic!(
					"BlockIndexListener: reorg to block at height {} which is higher than current tip {}",
					block.height, tip.height
				);
			}
		}


		let mut tip = self.tip.lock();
		*tip = Some(block);

		Ok(())
	}
}

#[tokio::test]
async fn test_block_index_basic_sync() {
	// Setup context and start bitcoind and postgres as in the minimal setup
	let mut ctx = TestContext::new_minimal("block_index/basic").await;

	// Initializes the postgres database and connects to it
	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	// Initializes a bitcoind and creates a client
	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	// Create the BlockIndex (should sync tip with deep_tip from bitcoind)
	let listeners = vec![Box::new(BlockIndexListener::new()) as Box<dyn ChainEventListener>];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut block_index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.expect("blockindex created");
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;

	// The current chain-tip is 104
	// However, we are only synced up-to the deep tip
	let chain_tip = block_index.chain_tip();
	let sync_height = block_index.sync_tip();
	assert_eq!(chain_tip.height, BlockHeight::new(104));
	assert_eq!(sync_height.height, BlockHeight::new(4));

	// Generate 20 blocks and validate that the index processes them correctly
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	bitcoind.generate_to_address(20, &addrs).expect("Generated 20 blocks");
	block_index.sync().await.expect("BlockIndex sync");
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;

	// The updated tip goes to block-height 124
	{
		let chain_tip = block_index.chain_tip();
		let sync_tip = block_index.sync_tip();

		let bitcoind_tip = bitcoind.tip().expect("Got bitcoind tip");
		assert_eq!(chain_tip.height, bitcoind_tip.height);
		assert_eq!(chain_tip.hash, bitcoind_tip.hash);
		assert_eq!(chain_tip.height, BlockHeight::new(124));

		// After sync, sync_tip should equal chain_tip
		assert_eq!(sync_tip.height, chain_tip.height);
		assert_eq!(sync_tip.hash, chain_tip.hash);
	}

	// Let's retrieve the details about the block at heigh 120
	let block_120 = {
		let local_block = db.read(async |t| t.get_block_by_height(BlockTable::Captaind, BlockHeight::new(120)).await).await.unwrap().unwrap();
		let bitcoin_block = bitcoind.get_block_by_height(BlockHeight::new(120)).unwrap();
		assert_eq!(local_block.hash, bitcoin_block.hash);
		assert_eq!(local_block.height, BlockHeight::new(120));
		assert_eq!(bitcoin_block.height, BlockHeight::new(120));
		local_block
	};

	// Let's invalidate this block and introduce a re-org
	// use a enw address so that bitcoind acceptst the new block
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf").unwrap().assume_checked();
	bitcoind.invalidate_block(&block_120.hash).expect("Invalidated block");
	bitcoind.generate_to_address(20, &addrs).expect("Generated 1 block");

	// Let's verify that our block-index manages this correctly
	block_index.sync().await.expect("BlockIndex sync");
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	{
		let bitcoind_tip = bitcoind.tip().expect("Got bitcoind tip");
		let chain_tip = block_index.chain_tip();
		let sync_tip = block_index.sync_tip();
		let db_tip = db.read(async |t| t.get_highest_block(BlockTable::Captaind).await).await.unwrap().unwrap();

		assert_eq!(chain_tip.height, bitcoind_tip.height);
		assert_eq!(chain_tip.hash, bitcoind_tip.hash);
		assert_eq!(bitcoind_tip.height, BlockHeight::new(139));
		assert_eq!(chain_tip.height, BlockHeight::new(139));
		assert_eq!(db_tip.height, BlockHeight::new(139));

		// After sync, sync_tip should equal chain_tip
		assert_eq!(sync_tip.height, chain_tip.height);
		assert_eq!(sync_tip.hash, chain_tip.hash);
	}
}

/// A listener that fails the first reorg after the startup rollback and
/// succeeds afterwards.
pub struct FailOnceReorgListener {
	calls: Arc<AtomicUsize>,
}

impl FailOnceReorgListener {
	pub fn new() -> Self {
		Self { calls: Arc::new(AtomicUsize::new(0)) }
	}
}

#[async_trait::async_trait]
impl ChainEventListener for FailOnceReorgListener {
	async fn on_mempool_update(&self, _raw: &RawMempool) -> anyhow::Result<()> {
		panic!("This should never be called")
	}

	async fn on_block_added(&self, _block: &BlockData) -> anyhow::Result<()> {
		Ok(())
	}

	async fn on_reorg(&self, _block: BlockRef) -> anyhow::Result<()> {
		let calls = self.calls.fetch_add(1, Ordering::SeqCst);
		if calls == 1 {
			bail!("simulated reorg failure");
		}
		Ok(())
	}
}

/// Regression test for the reorg ordering bug in `BlockIndex::org_out_blocks_above`.
///
/// If a listener fails while handling `on_reorg`, the in-memory sync height must
/// not be advanced until the listeners succeed and the orphaned rows are deleted.
/// Otherwise the next sync cycle no longer detects the reorg and wedges on the
/// duplicate block inserts.
#[tokio::test]
async fn test_block_index_reorg_retry() {
	let mut ctx = TestContext::new_minimal("block_index/reorg_retry").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	let listener = FailOnceReorgListener::new();
	let call_count = listener.calls.clone();
	let listeners = vec![Box::new(listener) as Box<dyn ChainEventListener>];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut block_index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.expect("blockindex created");

	// Sync up to the chain tip.
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	bitcoind.generate_to_address(20, &addrs).expect("Generated 20 blocks");
	block_index.sync().await.expect("BlockIndex sync");

	// Invalidate a block and mine replacements, causing a reorg.
	let block_120 = db.read(async |t| t.get_block_by_height(BlockTable::Captaind, BlockHeight::new(120)).await).await.unwrap().unwrap();
	let addrs2 = Address::<NetworkUnchecked>::from_str("bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf").unwrap().assume_checked();
	bitcoind.invalidate_block(&block_120.hash).expect("Invalidated block");
	bitcoind.generate_to_address(20, &addrs2).expect("Generated replacement blocks");

	// First sync should fail because the listener fails once.
	let result = block_index.sync().await;
	assert!(result.is_err(), "First sync should fail due to listener failure");

	// Second sync should re-detect the same reorg, retry, and converge.
	block_index.sync().await.expect("Second sync should succeed after retry");

	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;

	// The startup rollback, then one failure, then one success.
	assert_eq!(call_count.load(Ordering::SeqCst), 3);
}

/// Records the blocks it applied, optionally failing its first rollback.
#[derive(Clone)]
pub struct RecordingListener {
	blocks: Arc<parking_lot::Mutex<BTreeMap<BlockHeight, BlockHash>>>,
	fail_rollback: Arc<AtomicBool>,
	fail_block: Arc<AtomicBool>,
}

impl RecordingListener {
	pub fn new(fail_first_rollback: bool) -> Self {
		Self {
			blocks: Arc::new(parking_lot::Mutex::new(BTreeMap::new())),
			fail_rollback: Arc::new(AtomicBool::new(fail_first_rollback)),
			fail_block: Arc::new(AtomicBool::new(false)),
		}
	}

	/// Fails the next block delivered.
	pub fn fail_next_block(&self) {
		self.fail_block.store(true, Ordering::SeqCst);
	}

	/// Asserts the recorded blocks are exactly the chain above `start`.
	fn assert_matches_chain(&self, bitcoind: &BitcoinRpcClient, start: BlockHeight) {
		let tip = bitcoind.tip().unwrap();
		let expected = (start.to_u32() + 1..=tip.height.to_u32()).map(|h| {
			let block = bitcoind.get_block_by_height(BlockHeight::new(h)).unwrap();
			(block.height, block.hash)
		}).collect::<BTreeMap<_, _>>();
		assert_eq!(*self.blocks.lock(), expected);
	}
}

#[async_trait::async_trait]
impl ChainEventListener for RecordingListener {
	async fn on_mempool_update(&self, _raw: &RawMempool) -> anyhow::Result<()> {
		panic!("This should never be called")
	}

	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		if self.fail_block.swap(false, Ordering::SeqCst) {
			bail!("simulated block failure");
		}
		let prev = self.blocks.lock().insert(block.block_ref.height, block.block_ref.hash);
		assert!(prev.is_none_or(|h| h == block.block_ref.hash), "block replaced without a rollback");
		Ok(())
	}

	async fn on_reorg(&self, block: BlockRef) -> anyhow::Result<()> {
		let mut blocks = self.blocks.lock();
		if blocks.keys().any(|h| *h > block.height) && self.fail_rollback.swap(false, Ordering::SeqCst) {
			bail!("simulated reorg failure");
		}
		blocks.retain(|h, _| *h <= block.height);
		Ok(())
	}
}

/// Mines 20 blocks and reorgs them away from height 120 with a longer chain,
/// syncing the index on both sides. The second sync fails because one
/// listener fails, after the other one already rolled back.
///
/// Returns the orphaned block at height 120.
async fn sync_through_failed_reorg(
	index: &mut BlockIndex,
	db: &Db,
	bitcoind: &BitcoinRpcClient,
) -> BlockRef {
	let addr_a = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	let addr_b = Address::<NetworkUnchecked>::from_str("bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf").unwrap().assume_checked();

	bitcoind.generate_to_address(20, &addr_a).unwrap();
	index.sync().await.expect("initial sync");

	let block_120 = db.read(async |t| t.get_block_by_height(BlockTable::Captaind, BlockHeight::new(120)).await).await.unwrap().unwrap();
	bitcoind.invalidate_block(&block_120.hash).unwrap();
	bitcoind.generate_to_address(20, &addr_b).unwrap();
	index.sync().await.expect_err("one listener fails the reorg");

	block_120
}

/// A listener rolled back for a reorg that another listener failed. If the
/// chain then switches back to the original branch before the retry, the
/// rolled-back blocks must be replayed instead of trusted from the index.
#[tokio::test]
async fn test_block_index_failed_reorg_then_original_branch_returns() {
	let mut ctx = TestContext::new_minimal("block_index/failed_reorg_original_returns").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	let ok = RecordingListener::new(false);
	let failing = RecordingListener::new(true);
	let listeners = vec![
		Box::new(ok.clone()) as Box<dyn ChainEventListener>,
		Box::new(failing.clone()) as Box<dyn ChainEventListener>,
	];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.unwrap();

	let block_120 = sync_through_failed_reorg(&mut index, &db, &bitcoind).await;

	// Switch back to the original branch and extend it.
	let first_b = bitcoind.get_block_hash(120).unwrap();
	bitcoind.invalidate_block(&first_b).unwrap();
	bitcoind.call::<serde_json::Value>("reconsiderblock", &[block_120.hash.to_string().into()]).unwrap();
	assert_eq!(bitcoind.get_block_hash(120).unwrap(), block_120.hash);
	let addr_a = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	bitcoind.generate_to_address(2, &addr_a).unwrap();

	index.sync().await.expect("retry converges");

	assert_eq!(index.sync_tip(), bitcoind.tip().unwrap());
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	ok.assert_matches_chain(&bitcoind, birthday.height);
	failing.assert_matches_chain(&bitcoind, birthday.height);
}

/// A restart after a failed reorg must still roll back the listener that
/// failed it, even though the index no longer holds the orphaned blocks.
#[tokio::test]
async fn test_block_index_failed_reorg_then_restart() {
	let mut ctx = TestContext::new_minimal("block_index/failed_reorg_restart").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();

	let ok = RecordingListener::new(false);
	let failing = RecordingListener::new(true);
	let listeners = || vec![
		Box::new(ok.clone()) as Box<dyn ChainEventListener>,
		Box::new(failing.clone()) as Box<dyn ChainEventListener>,
	];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut index = BlockIndex::new(
		ctx.bitcoind().async_client(), db.clone(), listeners(), birthday, BlockTable::Captaind,
	).await.unwrap();

	sync_through_failed_reorg(&mut index, &db, &bitcoind).await;
	drop(index);

	let mut index = BlockIndex::new(
		ctx.bitcoind().async_client(), db.clone(), listeners(), birthday, BlockTable::Captaind,
	).await.unwrap();
	index.sync().await.expect("sync after restart");

	assert_eq!(index.sync_tip(), bitcoind.tip().unwrap());
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	ok.assert_matches_chain(&bitcoind, birthday.height);
	failing.assert_matches_chain(&bitcoind, birthday.height);
}

/// Shares a [BlockIndexListener] with the test while the block index owns it.
pub struct SharedListener(Arc<BlockIndexListener>);

#[async_trait::async_trait]
impl ChainEventListener for SharedListener {
	async fn on_mempool_update(&self, raw: &RawMempool) -> anyhow::Result<()> {
		self.0.on_mempool_update(raw).await
	}

	async fn on_block_added(&self, block: &BlockData) -> anyhow::Result<()> {
		self.0.on_block_added(block).await
	}

	async fn on_reorg(&self, block: BlockRef) -> anyhow::Result<()> {
		self.0.on_reorg(block).await
	}
}

/// The listeners processed a block whose commit result was lost. Sync must
/// continue after that block without leaving a gap for the listeners.
#[tokio::test]
async fn test_block_index_resumes_after_a_block_the_listeners_processed() {
	let mut ctx = TestContext::new_minimal("block_index/resume_after_processed_block").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	let listener = Arc::new(BlockIndexListener::new());
	let listeners = vec![Box::new(SharedListener(listener.clone())) as Box<dyn ChainEventListener>];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut block_index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.expect("blockindex created");

	// what add_block did before the result of its commit was lost
	let next = bitcoind.get_block_by_height(birthday.height + BlockDelta::new(1)).expect("next block");
	let block = bitcoind.get_block(&next.hash).expect("get block");
	listener.on_block_added(&BlockData { block_ref: next, block }).await.unwrap();
	db.write(async |t| t.store_block(BlockTable::Captaind, &next).await).await.unwrap();
	assert_eq!(block_index.sync_tip(), birthday);

	block_index.sync().await.expect("sync continues after the processed block");
	let bitcoind_tip = bitcoind.tip().expect("Got bitcoind tip");
	assert_eq!(block_index.sync_tip(), bitcoind_tip);
	assert_eq!(*listener.tip.lock(), Some(bitcoind_tip));
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
}

/// A listener that records the reorgs it is told about.
pub struct ReorgCountingListener {
	reorgs: Arc<AtomicUsize>,
	last_reorg: Arc<parking_lot::Mutex<Option<BlockRef>>>,
}

#[async_trait::async_trait]
impl ChainEventListener for ReorgCountingListener {
	async fn on_mempool_update(&self, _raw: &RawMempool) -> anyhow::Result<()> {
		panic!("This should never be called")
	}

	async fn on_block_added(&self, _block: &BlockData) -> anyhow::Result<()> {
		Ok(())
	}

	async fn on_reorg(&self, block: BlockRef) -> anyhow::Result<()> {
		self.reorgs.fetch_add(1, Ordering::SeqCst);
		*self.last_reorg.lock() = Some(block);
		Ok(())
	}
}

/// A commit whose result was lost leaves the block stored while the sync tip
/// stays at its parent. Sync must resume from the stored block, and process
/// it as a reorg if it was replaced on the chain.
#[tokio::test]
async fn test_block_index_recovers_from_committed_block_row() {
	let mut ctx = TestContext::new_minimal("block_index/committed_block_row").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	let reorgs = Arc::new(AtomicUsize::new(0));
	let last_reorg = Arc::new(parking_lot::Mutex::new(None));
	let listener = ReorgCountingListener { reorgs: reorgs.clone(), last_reorg: last_reorg.clone() };
	let listeners = vec![Box::new(listener) as Box<dyn ChainEventListener>];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut block_index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.expect("blockindex created");

	// the stored block is still on the chain
	let next = bitcoind.get_block_by_height(birthday.height + BlockDelta::new(1)).expect("next block");
	db.write(async |t| t.store_block(BlockTable::Captaind, &next).await).await.unwrap();
	assert_eq!(block_index.sync_tip(), birthday);

	block_index.sync().await.expect("sync resumes from the stored block");
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	// Only the startup rollback, to the stored block: it is not reorged out.
	assert_eq!(reorgs.load(Ordering::SeqCst), 1);
	assert_eq!(*last_reorg.lock(), Some(next));

	// the stored block was replaced on the chain
	let tip = block_index.sync_tip();
	let orphan = BlockRef { height: tip.height + BlockDelta::new(1), hash: birthday.hash };
	db.write(async |t| t.store_block(BlockTable::Captaind, &orphan).await).await.unwrap();
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	bitcoind.generate_to_address(1, &addrs).expect("Generated a block");

	block_index.sync().await.expect("the replaced block is reorged out");
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	assert_eq!(reorgs.load(Ordering::SeqCst), 2, "listeners must be told about the reorg");
	assert_eq!(*last_reorg.lock(), Some(tip), "the reorg goes back to the common ancestor");

	// a stored block that is the chain tip still counts as progress
	bitcoind.generate_to_address(1, &addrs).expect("Generated a block");
	let new_tip = bitcoind.tip().expect("Got bitcoind tip");
	db.write(async |t| t.store_block(BlockTable::Captaind, &new_tip).await).await.unwrap();
	assert!(block_index.sync().await.expect("sync"), "recovering the stored tip is progress");
	assert_eq!(block_index.sync_tip(), new_tip);

	// a reorg delete was committed but its result was lost
	let below = new_tip.height.saturating_sub(BlockDelta::new(1));
	db.write(async |t| t.remove_blocks_above(BlockTable::Captaind, below).await).await.unwrap();
	bitcoind.generate_to_address(1, &addrs).expect("Generated a block");
	block_index.sync().await.expect("sync resumes from the stored tip below the sync tip");
	assert_eq!(block_index.sync_tip(), bitcoind.tip().expect("Got bitcoind tip"));
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
}

/// A listener applied a block that another listener failed. If that block is
/// replaced before the retry, the listener must be rolled back to its parent.
#[tokio::test]
async fn test_block_index_failed_block_then_replaced() {
	let mut ctx = TestContext::new_minimal("block_index/failed_block_replaced").await;

	ctx.init_central_postgres().await;
	let postgres_cfg = ctx.new_postgres(&ctx.test_name).await;
	Db::create(&postgres_cfg).await.expect("Database created");
	let db = Db::connect(&postgres_cfg).await.expect("Connected to database");

	ctx.init_central_bitcoind().await;
	let bitcoind = ctx.bitcoind().sync_client();
	let bitcoind_async = ctx.bitcoind().async_client();

	let ok = RecordingListener::new(false);
	let failing = RecordingListener::new(false);
	let listeners = vec![
		Box::new(ok.clone()) as Box<dyn ChainEventListener>,
		Box::new(failing.clone()) as Box<dyn ChainEventListener>,
	];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut index = BlockIndex::new(bitcoind_async, db.clone(), listeners, birthday, BlockTable::Captaind).await.unwrap();
	index.sync().await.expect("initial sync");

	let addr_a = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	let addr_b = Address::<NetworkUnchecked>::from_str("bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf").unwrap().assume_checked();
	let parent = bitcoind.tip().unwrap();
	bitcoind.generate_to_address(1, &addr_a).unwrap();
	let orphan = bitcoind.tip().unwrap();
	failing.fail_next_block();
	index.sync().await.expect_err("one listener fails the block");
	assert_eq!(index.sync_tip(), parent);

	bitcoind.invalidate_block(&orphan.hash).unwrap();
	bitcoind.generate_to_address(2, &addr_b).unwrap();
	index.sync().await.expect("retry converges");

	assert_eq!(index.sync_tip(), bitcoind.tip().unwrap());
	check_block_index_is_consistent(&db, BlockTable::Captaind, &bitcoind).await;
	ok.assert_matches_chain(&bitcoind, birthday.height);
	failing.assert_matches_chain(&bitcoind, birthday.height);
}
