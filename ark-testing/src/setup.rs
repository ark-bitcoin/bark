use bitcoin::Amount;

use crate::{Aspd, Bitcoind, Bark, TestContext};

pub async fn setup_simple(name: &str) -> (TestContext, Bitcoind, Aspd, Bark, Bark) {
	let ctx = TestContext::new(name).await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;

	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;

	(ctx, bitcoind, aspd, bark1, bark2)
}

pub async fn setup_asp_funded(name: &str) -> (TestContext, Bitcoind, Aspd, Bark, Bark) {
	let (ctx, bitcoind, aspd, bark1, bark2) = setup_simple(name).await;

	// Fund the asp
	bitcoind.prepare_funds().await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	(ctx, bitcoind, aspd, bark1, bark2)
}

pub async fn setup_full(name: &str) -> (TestContext, Bitcoind, Aspd, Bark, Bark) {
	let (ctx, bitcoind, aspd, bark1, bark2) = setup_asp_funded(name).await;

	// Fund clients
	bitcoind.fund_bark(&bark1, Amount::from_sat(1_000_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(1_000_000)).await;
	bark2.onboard(Amount::from_sat(800_000)).await;

	// refresh vtxo
	bark1.onboard(Amount::from_sat(200_000)).await;
	bark1.refresh_all().await;
	// onboard vtxo
	bark1.onboard(Amount::from_sat(300_000)).await;
	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, Amount::from_sat(330_000)).await;

	(ctx, bitcoind, aspd, bark1, bark2)
}
