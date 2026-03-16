
use ark_testing::{sat, TestContext};

/// Verify that `POST /onchain/addresses/next` and `GET /onchain/balance` work end-to-end.
#[tokio::test]
async fn onchain_address_and_balance_barkd() {
	let ctx = TestContext::new("barkd/onchain_address_and_balance_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	let funded = sat(100_000);

	// onchain_address() calls POST /onchain/addresses/next
	let address = barkd.onchain_address().await;
	ctx.bitcoind().fund_addr(address, funded).await;
	ctx.generate_blocks(1).await;

	// onchain_balance() calls POST /onchain/sync then GET /onchain/balance
	let balance = barkd.onchain_balance().await;
	assert_eq!(balance, funded, "on-chain balance should equal funded amount");
}

/// Verify that `GET /onchain/utxos` and `GET /onchain/transactions` reflect funded state.
#[tokio::test]
async fn onchain_utxos_and_transactions_barkd() {
	let ctx = TestContext::new("barkd/onchain_utxos_and_transactions_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	let funded = sat(50_000);

	// Fund via the helper (which calls POST /onchain/addresses/next internally).
	ctx.fund_barkd(&barkd, funded).await;

	// onchain_balance() syncs the wallet so the subsequent reads see the funded UTXO.
	barkd.onchain_balance().await;

	let utxos = barkd.onchain_utxos().await;
	assert_eq!(utxos.len(), 1, "should have exactly one UTXO after funding");
	assert_eq!(utxos[0].amount, funded, "UTXO amount should match funded amount");

	let txns = barkd.onchain_transactions().await;
	assert_eq!(txns.len(), 1, "should have exactly one on-chain transaction after funding");
}
