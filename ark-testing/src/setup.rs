
use bitcoin::Amount;

use crate::{Aspd, Bark, TestContext};

pub struct TestSetup {
	pub aspd: Aspd,
	pub bark1: Bark,
	pub bark2: Bark,
	pub ctx: TestContext
}

pub async fn setup_simple(name: &str) -> TestSetup {
	let ctx = TestContext::new(name).await;

	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;

	TestSetup { aspd, bark1, bark2, ctx }
}

pub async fn setup_asp_funded(name: &str) -> TestSetup {
	let ctx = TestContext::new(name).await;

	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;

	let setup = TestSetup { aspd, bark1, bark2, ctx };

	setup.ctx.fund_asp(&setup.aspd, Amount::from_int_btc(10)).await;

	setup.ctx.bitcoind.generate(1).await;

	setup
}

pub async fn setup_full(name: &str) -> TestSetup {
	let ctx = TestContext::new(name).await;

	let aspd = ctx.new_aspd("aspd", None).await;
	let bark1 = ctx.new_bark("bark1", &aspd).await;
	let bark2 = ctx.new_bark("bark2", &aspd).await;

	let setup = TestSetup { aspd, bark1, bark2, ctx };

	setup.ctx.fund_asp(&setup.aspd, Amount::from_int_btc(10)).await;

	setup.ctx.bitcoind.generate(1).await;

	// Fund clients
	setup.ctx.fund_bark(&setup.bark1, Amount::from_sat(1_000_000)).await;
	setup.ctx.fund_bark(&setup.bark2, Amount::from_sat(1_000_000)).await;

	setup.ctx.bitcoind.generate(1).await;

	setup.bark2.onboard(Amount::from_sat(800_000)).await;

	// refresh vtxo
	setup.bark1.onboard(Amount::from_sat(200_000)).await;
	setup.ctx.bitcoind.generate(12).await;

	setup.bark1.refresh_all().await;

	// onboard vtxo
	setup.bark1.onboard(Amount::from_sat(300_000)).await;
	setup.ctx.bitcoind.generate(12).await;

	// oor vtxo
	setup.bark2.send_oor(&setup.bark1.vtxo_pubkey().await, Amount::from_sat(330_000)).await;

	setup
}
