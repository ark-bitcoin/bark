use bitcoin::Amount;

use crate::{Aspd, Bark, TestContext};

pub struct TestSetup {
	pub aspd: Aspd,
	pub bark1: Bark,
	pub bark2: Bark,
	pub context: TestContext
}

pub async fn setup_simple(name: &str) -> TestSetup {
	let mut context = TestContext::new(name).await;

	let aspd = context.new_aspd("aspd", None).await;
	let bark1 = context.new_bark("bark1", &aspd).await;
	let bark2 = context.new_bark("bark2", &aspd).await;

	TestSetup { aspd, bark1, bark2, context }
}

pub async fn setup_asp_funded(name: &str) -> TestSetup {
	let setup = setup_simple(name).await;

	setup.context.fund_asp(&setup.aspd, Amount::from_int_btc(10)).await;

	setup.context.bitcoind.generate(1).await;

	setup
}

pub async fn setup_full(name: &str) -> TestSetup {
	let setup = setup_asp_funded(name).await;

	// Fund clients
	setup.context.fund_bark(&setup.bark1, Amount::from_sat(1_000_000)).await;
	setup.context.fund_bark(&setup.bark2, Amount::from_sat(1_000_000)).await;

	setup.context.bitcoind.generate(1).await;

	setup.bark2.onboard(Amount::from_sat(800_000)).await;

	// refresh vtxo
	setup.bark1.onboard(Amount::from_sat(200_000)).await;
	setup.bark1.refresh_all().await;
	// onboard vtxo
	setup.bark1.onboard(Amount::from_sat(300_000)).await;
	// oor vtxo
	setup.bark2.send_oor(&setup.bark1.vtxo_pubkey().await, Amount::from_sat(330_000)).await;

	setup
}
