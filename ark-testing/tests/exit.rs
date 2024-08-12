
use ark_testing::context::TestContext;

use bitcoincore_rpc::bitcoin::amount::Amount;


#[tokio::test]
async fn unilateral_exit() {
	// Initialize the test
	let ctx = TestContext::new("unilateral_exit");
	let bitcoind = ctx.bitcoind("bitcoind-1").await.unwrap();
	let aspd = ctx.aspd("aspd-1", &bitcoind).await.unwrap();

	// Fund the asp
	bitcoind.generate(106).await.unwrap();
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await.unwrap();

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await.unwrap();
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await.unwrap();
	bitcoind.fund_bark(&bark1, Amount::from_sat(90_000_000)).await.unwrap();
	bitcoind.fund_bark(&bark2, Amount::from_sat(5_000_000)).await.unwrap();
	bark1.onboard(Amount::from_sat(80_000_000)).await.unwrap();

	let pk1 = bark1.get_vtxo_pubkey().await.unwrap();
	let pk2 = bark2.get_vtxo_pubkey().await.unwrap();

	bark1.send_round(pk2, Amount::from_sat(50_000_000)).await.unwrap();
	bark2.send_oor(pk1, Amount::from_sat(20_000_000)).await.unwrap();

	assert_eq!(50_000_000, bark1.offchain_balance().await.unwrap().to_sat());
	assert_eq!(29_998_035, bark2.offchain_balance().await.unwrap().to_sat());
	assert_eq!(9_997_973, bark1.onchain_balance().await.unwrap().to_sat());
	assert_eq!(5_000_000, bark2.onchain_balance().await.unwrap().to_sat());

	// exit on bark1
	bark1.start_exit().await.unwrap();
	// fees paid should be subtracted
	assert_eq!(9_889_663, bark1.onchain_balance().await.unwrap().to_sat());

	bitcoind.generate(11).await.unwrap();
	bark1.claim_exit().await.unwrap();
	// nothing should have changed yet
	assert_eq!(9_889_663, bark1.onchain_balance().await.unwrap().to_sat());

	bitcoind.generate(1).await.unwrap();
	bark1.claim_exit().await.unwrap();
	// then it should have landed
	assert_eq!(59_869_163, bark1.onchain_balance().await.unwrap().to_sat());

	// bark2.start_exit().await.unwrap();
	// assert_eq!(1, bark2.onchain_balance().await.unwrap().to_sat());
	// assert_eq!(1, bark2.onchain_balance().await.unwrap().to_sat());
}


