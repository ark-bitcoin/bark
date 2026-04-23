
use ark_testing::{sat, TestContext};

use super::helpers::wait_for_onchain_balance;

/// Verify that `POST /onchain/addresses/next` and `GET /onchain/balance` work end-to-end.
#[tokio::test]
async fn onchain_address_and_balance_barkd() {
	let ctx = TestContext::new("barkd/onchain_address_and_balance_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let funded = sat(100_000);
	let barkd = ctx.barkd("barkd1", &srv).funded(funded).create().await;

	wait_for_onchain_balance(&barkd, funded).await;
	let balance = barkd.onchain_balance().await;
	assert_eq!(balance, funded, "on-chain balance should equal funded amount");
}

/// Verify that `GET /onchain/utxos` and `GET /onchain/transactions` reflect funded state.
#[tokio::test]
async fn onchain_utxos_and_transactions_barkd() {
	let ctx = TestContext::new("barkd/onchain_utxos_and_transactions_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let funded = sat(50_000);
	let barkd = ctx.barkd("barkd1", &srv).funded(funded).create().await;

	wait_for_onchain_balance(&barkd, funded).await;

	let utxos = barkd.onchain_utxos().await;
	assert_eq!(utxos.len(), 1, "should have exactly one UTXO after funding");
	assert_eq!(utxos[0].amount, funded, "UTXO amount should match funded amount");

	let txns = barkd.onchain_transactions().await;
	assert_eq!(txns.len(), 1, "should have exactly one on-chain transaction after funding");
}
