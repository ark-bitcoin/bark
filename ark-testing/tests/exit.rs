
use ark_testing::daemon::bitcoind::BitcoindConfig;
use ark_testing::context::TestContext;

use bitcoin::FeeRate;
use bitcoincore_rpc::bitcoin::amount::Amount;


#[tokio::test]
async fn unilateral_exit() {
	// Initialize the test
	let ctx = TestContext::new("unilateral_exit").await;
	let bitcoind = ctx.bitcoind_with_cfg("bitcoind", BitcoindConfig {
		relay_fee: Some(FeeRate::from_sat_per_vb(1).unwrap()),
		..ctx.bitcoind_default_cfg("bitcoind")
	}).await;
	let aspd = ctx.aspd("aspd", &bitcoind).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark1, Amount::from_sat(90_000_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(5_000_000)).await;
	bark1.onboard(Amount::from_sat(80_000_000)).await;

	let pk1 = bark1.vtxo_pubkey().await;
	let pk2 = bark2.vtxo_pubkey().await;

	bark1.send_round(pk2, Amount::from_sat(50_000_000)).await;
	bark2.send_oor(pk1, Amount::from_sat(20_000_000)).await;

	assert_eq!(50_000_000, bark1.offchain_balance().await.to_sat());
	assert_eq!(29_998_035, bark2.offchain_balance().await.to_sat());
	assert_eq!(9_997_973, bark1.onchain_balance().await.to_sat());
	assert_eq!(5_000_000, bark2.onchain_balance().await.to_sat());

	// exit on bark1
	bark1.start_exit().await;
	// fees paid should be subtracted
	assert_eq!(9_889_663, bark1.onchain_balance().await.to_sat());

	bitcoind.generate(11).await;
	bark1.claim_exit().await;
	// nothing should have changed yet
	assert_eq!(9_889_663, bark1.onchain_balance().await.to_sat());

	bitcoind.generate(1).await;
	bark1.claim_exit().await;
	// then it should have landed
	assert_eq!(59_869_163, bark1.onchain_balance().await.to_sat());

	// bark2.start_exit().await;
	// assert_eq!(1, bark2.onchain_balance().await.to_sat());
	// assert_eq!(1, bark2.onchain_balance().await.to_sat());
}


