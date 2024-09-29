
use ark_testing::daemon::bitcoind::BitcoindConfig;
use ark_testing::{context::TestContext, Bark, Bitcoind};

use bitcoin::FeeRate;
use bitcoincore_rpc::bitcoin::amount::Amount;
use bitcoincore_rpc::RpcApi;

async fn progress_exit(
	bitcoind: &Bitcoind,
	w: &Bark,
) {
	let mut flip = false;
	for _ in 0..20 {
		let res = w.exit().await;
		if res.done {
			return;
		}
		if let Some(height) = res.height {
			let current = bitcoind.sync_client().get_block_count().unwrap();
			bitcoind.generate(height as u64 - current).await;
		} else {
			flip = if flip {
				bitcoind.generate(1).await;
				false
			} else {
				true
			};
		}
	}
	panic!("failed to finish unilateral exit of bark {}", w.name());
}

#[tokio::test]
async fn unilateral_exit() {
	// Initialize the test
	let ctx = TestContext::new("unilateral_exit").await;
	let bitcoind = ctx.bitcoind_with_cfg("bitcoind", BitcoindConfig {
		relay_fee: Some(FeeRate::from_sat_per_vb(8).unwrap()),
		..ctx.bitcoind_default_cfg("bitcoind")
	}).await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;
	let bark3 = ctx.bark("bark3".to_string(), &bitcoind, &aspd).await;
	let bark4 = ctx.bark("bark4".to_string(), &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark1, Amount::from_sat(90_000_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(5_000_000)).await;
	bitcoind.fund_bark(&bark3, Amount::from_sat(90_000_000)).await;
	bitcoind.fund_bark(&bark4, Amount::from_sat(5_000_000)).await;
	bark1.onboard(Amount::from_sat(80_000_000)).await;
	bark3.onboard(Amount::from_sat(80_000_000)).await;
	bitcoind.generate(1).await;

	let pk1 = bark1.vtxo_pubkey().await;
	let pk2 = bark2.vtxo_pubkey().await;
	let pk3 = bark3.vtxo_pubkey().await;
	let pk4 = bark4.vtxo_pubkey().await;

	// try make sure they send in the same round, so that the have identical exit txs
	tokio::join!(
		bark1.send_round(pk2, Amount::from_sat(50_000_000)),
		bark3.send_round(pk4, Amount::from_sat(50_000_000))
	);
	bark2.send_oor(pk3, Amount::from_sat(20_000_000)).await;
	bark4.send_oor(pk1, Amount::from_sat(20_000_000)).await;

	assert_eq!(50_000_000, bark1.offchain_balance().await.to_sat());
	assert_eq!(29_998_035, bark2.offchain_balance().await.to_sat());
	assert_eq!(50_000_000, bark3.offchain_balance().await.to_sat());
	assert_eq!(29_998_035, bark4.offchain_balance().await.to_sat());
	assert_eq!(9_996_895, bark1.onchain_balance().await.to_sat());
	assert_eq!(5_000_000, bark2.onchain_balance().await.to_sat());
	assert_eq!(9_996_895, bark3.onchain_balance().await.to_sat());
	assert_eq!(5_000_000, bark4.onchain_balance().await.to_sat());

	bitcoind.generate(1).await;
	progress_exit(&bitcoind, &bark1).await;
	assert_eq!(59_977_933, bark1.onchain_balance().await.to_sat());

	bitcoind.generate(1).await;
	progress_exit(&bitcoind, &bark2).await;
	assert_eq!(34_988_483, bark2.onchain_balance().await.to_sat());

	// the amounts of the following two are a tiny bit higher because their tree was
	// a bit smaller
	bitcoind.generate(1).await;
	progress_exit(&bitcoind, &bark3).await;
	assert_eq!(59_990_133, bark3.onchain_balance().await.to_sat());

	bitcoind.generate(1).await;
	progress_exit(&bitcoind, &bark4).await;
	assert_eq!(34_996_095, bark4.onchain_balance().await.to_sat());
}
