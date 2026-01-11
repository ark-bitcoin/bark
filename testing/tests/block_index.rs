use std::str::FromStr;

use bitcoin::{Address, address::NetworkUnchecked};


use bitcoin_ext::BlockRef;
use bitcoin_ext::rpc::{BitcoinRpcExt, BitcoinRpcClient, RpcApi};

use server::sync::{ChainEventListener, RawMempool, BlockData};
use server::sync::block_index::{BlockIndex};
use server::database::Db;

use ark_testing::TestContext;

/// Checks that the block index is fully consistent with the bitcoind chain
async fn check_block_index_is_consistent(db: &Db, bitcoind: &BitcoinRpcClient) {

	let lowest_block = db.get_lowest_block().await.unwrap().unwrap();
	let highest_block = db.get_highest_block().await.unwrap().unwrap();

	for height in lowest_block.height..=highest_block.height {
		let bitcoind_block = bitcoind.get_block_by_height(height).unwrap();
		let db_block = db.get_block_by_height(height).await.unwrap().unwrap();

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
				if block.block_ref.height == prev.height + 1 {
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

	// Create the BlockIndex (should sync tip with deep_tip from bitcoind)
	let listeners = vec![Box::new(BlockIndexListener::new()) as Box<dyn ChainEventListener>];
	let birthday = bitcoind.deep_tip().expect("deep tip");
	let mut block_index = BlockIndex::new(bitcoind.clone(), db.clone(), listeners, birthday).await.expect("blockindex created");
	check_block_index_is_consistent(&db, &bitcoind).await;

	// The current chain-tip is 104
	// However, we are only synced up-to the deep tip
	let chain_tip = block_index.chain_tip();
	let sync_height = block_index.sync_tip();
	assert_eq!(chain_tip.height, 104);
	assert_eq!(sync_height.height, 4);

	// Generate 20 blocks and validate that the index processes them correctly
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1p28cpcjynxvz3pyvd99wu7f5uxxkflttec6t4sxndxdsgtxksnp7q90rfcv").unwrap().assume_checked();
	bitcoind.generate_to_address(20, &addrs).expect("Generated 20 blocks");
	block_index.sync().await.expect("BlockIndex sync");
	check_block_index_is_consistent(&db, &bitcoind).await;

	// The updated tip goes to block-height 124
	{
		let chain_tip = block_index.chain_tip();
		let sync_tip = block_index.sync_tip();

		let bitcoind_tip = bitcoind.tip().expect("Got bitcoind tip");
		assert_eq!(chain_tip.height, bitcoind_tip.height);
		assert_eq!(chain_tip.hash, bitcoind_tip.hash);
		assert_eq!(chain_tip.height, 124);

		// After sync, sync_tip should equal chain_tip
		assert_eq!(sync_tip.height, chain_tip.height);
		assert_eq!(sync_tip.hash, chain_tip.hash);
	}

	// Let's retrieve the details about the block at heigh 120
	let block_120 = {
		let local_block = db.get_block_by_height(120).await.unwrap().unwrap();
		let bitcoin_block = bitcoind.get_block_by_height(120).unwrap();
		assert_eq!(local_block.hash, bitcoin_block.hash);
		assert_eq!(local_block.height, 120);
		assert_eq!(bitcoin_block.height, 120);
		local_block
	};

	// Let's invalidate this block and introduce a re-org
	// use a enw address so that bitcoind acceptst the new block
	let addrs = Address::<NetworkUnchecked>::from_str("bcrt1pnvttf55269k90h8r4xcwewqr9nvlyngge06srk4gmddu6sjjk9gq82vrkf").unwrap().assume_checked();
	bitcoind.invalidate_block(&block_120.hash).expect("Invalidated block");
	bitcoind.generate_to_address(20, &addrs).expect("Generated 1 block");

	// Let's verify that our block-index manages this correctly
	block_index.sync().await.expect("BlockIndex sync");
	check_block_index_is_consistent(&db, &bitcoind).await;
	{
		let bitcoind_tip = bitcoind.tip().expect("Got bitcoind tip");
		let chain_tip = block_index.chain_tip();
		let sync_tip = block_index.sync_tip();
		let db_tip = db.get_highest_block().await.unwrap().unwrap();

		assert_eq!(chain_tip.height, bitcoind_tip.height);
		assert_eq!(chain_tip.hash, bitcoind_tip.hash);
		assert_eq!(bitcoind_tip.height, 139);
		assert_eq!(chain_tip.height, 139);
		assert_eq!(db_tip.height, 139);

		// After sync, sync_tip should equal chain_tip
		assert_eq!(sync_tip.height, chain_tip.height);
		assert_eq!(sync_tip.hash, chain_tip.hash);
	}
}

