
#[macro_use]
extern crate ark_testing;

use ark_testing::daemon::bitcoind::BitcoindConfig;
use ark_testing::{context::TestContext, Bark, Bitcoind};
use bark_json::cli::VtxoType;

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
async fn exit_round() {
	// Initialize the test
	let ctx = TestContext::new("exit/exit_round").await;
	let bitcoind = ctx.bitcoind_with_cfg("bitcoind", BitcoindConfig {
		..ctx.bitcoind_default_cfg("bitcoind")
	}).await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;

	// Fund the asp
	bitcoind.prepare_funds().await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;
	let bark3 = ctx.bark("bark3".to_string(), &bitcoind, &aspd).await;
	let bark4 = ctx.bark("bark4".to_string(), &bitcoind, &aspd).await;
	let bark5 = ctx.bark("bark5".to_string(), &bitcoind, &aspd).await;
	let bark6 = ctx.bark("bark6".to_string(), &bitcoind, &aspd).await;
	let bark7 = ctx.bark("bark7".to_string(), &bitcoind, &aspd).await;
	let bark8 = ctx.bark("bark8".to_string(), &bitcoind, &aspd).await;

	tokio::join!(
		bitcoind.fund_bark(&bark1, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark2, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark3, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark4, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark5, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark6, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark7, Amount::from_sat(1_000_000)),
		bitcoind.fund_bark(&bark8, Amount::from_sat(1_000_000)),
	);
	bitcoind.generate(1).await;

	tokio::join!(
		bark1.onboard(Amount::from_sat(500_000)),
		bark2.onboard(Amount::from_sat(500_000)),
		bark3.onboard(Amount::from_sat(500_000)),
		bark4.onboard(Amount::from_sat(500_000)),
		bark5.onboard(Amount::from_sat(500_000)),
		bark6.onboard(Amount::from_sat(500_000)),
		bark7.onboard(Amount::from_sat(500_000)),
		bark8.onboard(Amount::from_sat(500_000)),
	);
	bitcoind.generate(7).await;

	tokio::join!(
		bark1.refresh_all(),
		bark2.refresh_all(),
		bark3.refresh_all(),
		bark4.refresh_all(),
		bark5.refresh_all(),
		bark6.refresh_all(),
		bark7.refresh_all(),
		bark8.refresh_all(),
	);

		// We don't need ASP for exits.
	aspd.stop().await.unwrap();
	progress_exit(&bitcoind, &bark1).await;
	progress_exit(&bitcoind, &bark2).await;
	progress_exit(&bitcoind, &bark3).await;
	progress_exit(&bitcoind, &bark4).await;
	progress_exit(&bitcoind, &bark5).await;
	progress_exit(&bitcoind, &bark6).await;
	progress_exit(&bitcoind, &bark7).await;
	progress_exit(&bitcoind, &bark8).await;

	// All wallets habe 1_000_000 sats of funds minus fees
	//
	// However, what fees are paid by which client is not fully predictable
	// This depends on the shape of the tree and the order of the exit
	//
	// We can't control the shape of the tree in the test.
	// The order of the exit is also somewhat random
	assert!(Amount::from_sat(978_856) <= bark1.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark2.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark3.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark4.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark5.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark6.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark7.onchain_balance().await);
	assert!(Amount::from_sat(978_856) <= bark8.onchain_balance().await);
}

#[tokio::test]
async fn exit_after_onboard() {
	let ctx = TestContext::new("exit/exit_after_onboard").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;

	bitcoind.prepare_funds().await;

	// Fund the bark instance
	let bark = ctx.bark("bark", &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark, Amount::from_sat(1_000_000)).await;

	// Onboard funds
	bark.onboard(Amount::from_sat(900_000)).await;

	// Exit unilaterally
	aspd.stop().await.unwrap();
	progress_exit(&bitcoind, &bark).await;

	assert!(bark.onchain_balance().await > Amount::from_sat(900_000),
		"The balance has been returned");
}

#[tokio::test]
async fn exit_oor() {
	let ctx = TestContext::new("exit/exit_oor").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let mut aspd = ctx.aspd("aspd", &bitcoind, None).await;

	bitcoind.prepare_funds().await;

	// Bark1 will pay bark2 oor.
	// Bark2 will attempt an exit
	let bark1 = ctx.bark("bark1", &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2", &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark1, Amount::from_sat(1_000_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(1_000_000)).await;

	// Bark1 onboard funds and sends some part to bark2
	bark1.onboard(Amount::from_sat(900_000)).await;
	let bark2_pubkey = bark2.vtxo_pubkey().await;
	bark1.send_oor(bark2_pubkey, Amount::from_sat(100_000)).await;

	// By calling bark2 vtxos we ensure the wallet is synced
	// This ensures bark2 knows the vtxo exists
	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have received one vtxo");
	assert_eq!(vtxos[0].vtxo_type, VtxoType::Oor);

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark2 exit and check the balance
	// It should be FUND_AMOUNT + VTXO_AMOUNT - fees
	progress_exit(&bitcoind, &bark2).await;
	assert_eq!(bark2.onchain_balance().await, Amount::from_sat(1_087_581));
}

