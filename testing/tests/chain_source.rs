use std::collections::HashSet;
use std::time::Duration;

use bitcoin::{BlockHash, Network, OutPoint, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256::HashEngine;

use bark::chain::ChainSource;
use bitcoin_ext::{BlockHeight, TxStatus};

use ark_testing::{sat, Bitcoind, TestContext};
use ark_testing::util::{get_bark_chain_source_from_env, TestContextChainSource};

async fn setup_chain_source(name: impl AsRef<str>) -> (TestContext, ChainSource) {
	let mut ctx = TestContext::new_minimal(name).await;
	ctx.init_central_bitcoind().await;
	ctx.init_central_electrs().await;

	let chain_source = match get_bark_chain_source_from_env() {
		TestContextChainSource::BitcoinCore => {
			ctx.bitcoind.as_ref().expect("bitcoind is not started").chain_source()
		}
		TestContextChainSource::ElectrsRest(_) => {
			ctx.electrs.as_ref().expect("electrs is not started").chain_source()
		}
	};
	(ctx, ChainSource::new(chain_source, Network::Regtest, None).await
		.expect("failed to create chain source client"))
}

async fn test_bitcoind(ctx: &TestContext, id: usize) -> Bitcoind {
	let name = format!("test_bitcoind{}", id);
	let mut config = ctx.bitcoind_default_cfg(&name);
	config.wallet = true;
	ctx.new_bitcoind_with_cfg(&name, config).await
}

#[tokio::test]
async fn chain_source_tip() {
	let (ctx, chain_source) = setup_chain_source("chain_source/tip").await;
	let start_height = ctx.bitcoind().get_block_count().await as BlockHeight;
	assert_eq!(chain_source.tip().await.unwrap(), start_height);

	// The tip should be updated when blocks are generated.
	ctx.generate_blocks(10).await;
	assert_eq!(chain_source.tip().await.unwrap(), start_height + 10);

	// The tip should stay the same when blocks are not generated.
	for _ in 0..10 {
		assert_eq!(chain_source.tip().await.unwrap(), start_height + 10);
		tokio::time::sleep(Duration::from_millis(10)).await;
	}

	// The tip should continue to be updated when new blocks are generated.
	ctx.generate_blocks(37).await;
	assert_eq!(chain_source.tip().await.unwrap(), start_height + 47);

	ctx.generate_blocks(1234).await;
	assert_eq!(chain_source.tip().await.unwrap(), start_height + 1281);

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.tip().await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_block_ref() {
	let (ctx, chain_source) = setup_chain_source("chain_source/block_ref").await;
	let start_height = ctx.bitcoind().get_block_count().await as BlockHeight;

	chain_source.block_ref(1000).await
		.expect_err("Invalid block heights should error");

	// Generating blocks shouldn't change results
	let start_block_ref = chain_source.block_ref(start_height).await.unwrap();
	ctx.generate_blocks(10).await;
	assert_eq!(chain_source.block_ref(start_height).await.unwrap(), start_block_ref);

	// Ensure each block hash is unique
	let mut hash_set = HashSet::with_capacity((start_height + 10) as usize);
	for i in 0..start_height + 10 {
		let block_ref = chain_source.block_ref(i).await.unwrap();
		assert!(hash_set.insert(block_ref.hash));
	}

	// Ensure block IDs can be queried as new blocks are produced
	chain_source.block_ref(start_height + 11).await
		.expect_err("Block Ref should not be valid");
	for i in 0..10 {
		ctx.generate_blocks(1).await;
		chain_source.block_ref(start_height + 10 + i).await
			.expect("Block Ref should be valid");
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.block_ref(start_height).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_block() {
	let (ctx, chain_source) = setup_chain_source("chain_source/block").await;
	let start_height = ctx.bitcoind().get_block_count().await as BlockHeight;
	let start_hash = chain_source.block_ref(start_height).await.unwrap().hash;

	// Ensure we can retrieve blocks by hash
	chain_source.block(start_hash).await.expect("Hash should be valid");

	// Ensure invalid hashes succeed with an empty result
	let invalid_hash = BlockHash::from_engine(HashEngine::default());
	let empty_result = chain_source.block(invalid_hash).await
		.expect("Invalid hash should not error");
	assert!(matches!(empty_result, None));

	// Generating blocks shouldn't change results
	let mut headers = HashSet::with_capacity(start_height as usize);
	for i in 0..10 {
		ctx.generate_blocks(1).await;
		let block_ref = chain_source.block_ref(i).await.expect("Block Ref should be valid");
		match chain_source.block(block_ref.hash).await.expect("Hash should be valid") {
			None => panic!("Hash should not return an empty result"),
			Some(block) => assert!(headers.insert(block.header)),
		}
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.block(start_hash).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_txs_spending_inputs() {
	let (ctx, chain_source) = setup_chain_source("chain_source/txs_spending_inputs").await;
	let h = ctx.bitcoind().get_block_count().await as BlockHeight;

	// Generate 5 out-points to track in 5 different bitcoind instances
	let mut bitcoinds = Vec::with_capacity(5);
	for i in 0..bitcoinds.capacity() {
		bitcoinds.push(test_bitcoind(&ctx, i).await);
	}
	let mut outpoints = Vec::with_capacity(bitcoinds.capacity());
	for i in 0..outpoints.capacity() {
		let address = bitcoinds[i].get_new_address();
		let script = ScriptBuf::from(address.clone());

		let txid = ctx.bitcoind().fund_addr(address, sat(1_000_000)).await;
		ctx.generate_blocks(1).await;

		let tx = chain_source.get_tx(&txid).await.unwrap()
			.expect("Transaction should exist");
		for (i, out) in tx.output.iter().enumerate() {
			if out.script_pubkey == script {
				outpoints.push(OutPoint {
					txid,
					vout: i as u32,
				});
				break;
			}
		}
	}
	assert_eq!(outpoints.len(), bitcoinds.len());

	// We should get no results when using fake outpoints
	let result = chain_source.txs_spending_inputs(
			[OutPoint { txid: Hash::from_engine(HashEngine::default()), vout: 0 }], h
		).await
		.expect("Should not error");
	assert!(result.map.is_empty());

	// We should get no results when outpoints haven't been spent
	let result = chain_source.txs_spending_inputs(outpoints.clone(), h).await
		.expect("Should not error");
	assert!(result.map.is_empty());

	// Results should be unchanged after generating blocks
	ctx.generate_blocks(10).await;
	let result = chain_source.txs_spending_inputs(outpoints.clone(), h).await
		.expect("Should not error");
	assert!(result.map.is_empty());

	// Pending and confirmed transactions should be returned successfully
	let ctx_address = ctx.bitcoind().get_new_address();
	let mut confirmed_txids = HashSet::from([
		bitcoinds[0].fund_addr(&ctx_address, sat(900_000)).await,
		bitcoinds[1].fund_addr(&ctx_address, sat(900_000)).await,
	]);
	ctx.generate_blocks(1).await;
	let start_height = ctx.bitcoind().get_block_count().await as BlockHeight;
	let mut unconfirmed_txids = HashSet::from([
		bitcoinds[2].fund_addr(&ctx_address, sat(900_000)).await,
		bitcoinds[3].fund_addr(&ctx_address, sat(900_000)).await,
		bitcoinds[4].fund_addr(&ctx_address, sat(900_000)).await,
	]);
	for txid in &unconfirmed_txids {
		ctx.await_transaction(*txid).await;
	}

	// We should have a mixture of confirmed and unconfirmed transactions
	let result = chain_source.txs_spending_inputs(outpoints.clone(), start_height)
		.await
		.expect("Should not error");
	assert_eq!(result.confirmed_txids().count(), confirmed_txids.len());
	assert_eq!(result.mempool_txids().count(), unconfirmed_txids.len());

	// Verify each out-point has been spent either in a block or in the mempool
	for outpoint in &outpoints {
		match result.get(outpoint).unwrap() {
			(txid, TxStatus::Confirmed(..)) => {
				assert!(confirmed_txids.remove(txid));
			}
			(txid, TxStatus::Mempool) => {
				assert!(unconfirmed_txids.remove(txid));
			}
			_ => panic!("We shouldn't have any other TxStatus"),
		}
	}
	assert!(confirmed_txids.is_empty());
	assert!(unconfirmed_txids.is_empty());

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.txs_spending_inputs(outpoints, 0).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_get_tx() {
	let (ctx, chain_source) = setup_chain_source("chain_source/get_tx").await;
	let test_bitcoind = test_bitcoind(&ctx, 0).await;

	// Ensure invalid transaction don't error
	let invalid = chain_source.get_tx(&Hash::from_engine(HashEngine::default())).await
		.expect("Invalid transactions shouldn't error");
	assert!(matches!(invalid, None));

	// Ensure pending transactions are returned
	let test_address = test_bitcoind.get_new_address();
	let pending = ctx.bitcoind().fund_addr(&test_address, sat(1_000_000)).await;
	ctx.await_transaction(pending).await;
	let pending_result = chain_source.get_tx(&pending).await
		.expect("Unconfirmed transactions are valid");
	assert!(matches!(pending_result, Some(_)));

	// Ensure confirmed transactions are returned
	ctx.generate_blocks(1).await;
	let confirmed_result = chain_source.get_tx(&pending).await
		.expect("Confirmed transactions are valid");

	match confirmed_result {
		None => panic!("Transaction is missing"),
		Some(tx) => assert!(tx.output.iter().any(|o| {
			o.script_pubkey == test_address.script_pubkey() && o.value == sat(1_000_000)
		})),
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.get_tx(&pending).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_tx_confirmed() {
	let (ctx, chain_source) = setup_chain_source("chain_source/tx_confirmed").await;
	let test_bitcoind = test_bitcoind(&ctx, 0).await;

	// Ensure invalid transaction don't error
	let invalid = chain_source.tx_confirmed(Hash::from_engine(HashEngine::default())).await
		.expect("Invalid transactions shouldn't error");
	assert!(matches!(invalid, None));

	// Ensure pending transactions are returned
	let test_address = test_bitcoind.get_new_address();
	let pending = ctx.bitcoind().fund_addr(&test_address, sat(1_000_000)).await;
	ctx.await_transaction(pending).await;
	let pending_result = chain_source.tx_confirmed(pending).await
		.expect("Unconfirmed transactions are valid");
	assert!(matches!(pending_result, None));

	// Ensure confirmed transactions are returned
	ctx.generate_blocks(1).await;
	let confirmed_result = chain_source.tx_confirmed(pending).await
		.expect("Confirmed transactions are valid");
	match confirmed_result {
		Some(h) => assert_eq!(h, ctx.bitcoind().get_block_count().await as BlockHeight),
		None => panic!("Transaction should be confirmed"),
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.tx_confirmed(pending).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_tx_status() {
	let (ctx, chain_source) = setup_chain_source("chain_source/tx_status").await;
	let test_bitcoind = test_bitcoind(&ctx, 0).await;

	// Ensure invalid transaction don't error
	let invalid = chain_source.tx_status(Hash::from_engine(HashEngine::default())).await
		.expect("Invalid transactions shouldn't error");
	assert!(matches!(invalid, TxStatus::NotFound));

	// Ensure pending transactions are returned
	let test_address = test_bitcoind.get_new_address();
	let pending = ctx.bitcoind().fund_addr(&test_address, sat(1_000_000)).await;
	ctx.await_transaction(pending).await;
	let pending_result = chain_source.tx_status(pending).await
		.expect("Unconfirmed transactions are valid");
	assert!(matches!(pending_result, TxStatus::Mempool));

	// Ensure confirmed transactions are returned
	ctx.generate_blocks(1).await;
	let confirmed_result = chain_source.tx_status(pending).await
		.expect("Confirmed transactions are valid");
	match confirmed_result {
		TxStatus::Confirmed(block) => {
			assert_eq!(block.height, ctx.bitcoind().get_block_count().await as BlockHeight)
		},
		_ => panic!("Transaction should be confirmed"),
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.tx_status(pending).await
		.expect_err("We shouldn't be able to retrieve data");
}

#[tokio::test]
async fn chain_source_txout_value() {
	let (ctx, chain_source) = setup_chain_source("chain_source/txout_value").await;
	let test_bitcoind = test_bitcoind(&ctx, 0).await;

	// Generate out-points to check
	let amounts = (1..=10).map(|v| sat(v * 100_000)).collect::<Vec<_>>();
	let mut outpoints = Vec::with_capacity(amounts.len());
	for i in 0..amounts.len() {
		let address = test_bitcoind.get_new_address();
		let script = ScriptBuf::from(address.clone());
		let txid = ctx.bitcoind().fund_addr(address, amounts[i]).await;
		ctx.await_transaction(txid).await;

		let tx = chain_source.get_tx(&txid).await.unwrap()
			.expect("Transaction should exist");
		for (i, out) in tx.output.iter().enumerate() {
			if out.script_pubkey == script {
				outpoints.push(OutPoint {
					txid,
					vout: i as u32,
				});
				break;
			}
		}
	}
	assert_eq!(outpoints.len(), amounts.len());

	// Ensure unconfirmed transactions are returned
	for (i, outpoint) in outpoints.iter().enumerate() {
		let amount = chain_source.txout_value(&outpoint).await
			.expect("Unconfirmed transactions are valid");
		assert_eq!(amount, amounts[i]);
	}

	// Ensure confirmed transactions are returned
	ctx.generate_blocks(1).await;
	for (i, outpoint) in outpoints.iter().enumerate() {
		let amount = chain_source.txout_value(&outpoint).await
			.expect("Unconfirmed transactions are valid");
		assert_eq!(amount, amounts[i]);
	}

	// Ensure network problems result in errors
	drop(ctx);
	chain_source.txout_value(&outpoints[0]).await
		.expect_err("We shouldn't be able to retrieve data");
}
