#[macro_use]
extern crate log;

use std::time::Duration;

use bark_json::cli::VtxoInfo;
use bitcoincore_rpc::bitcoin::amount::Amount;

use ark_testing::{AspdConfig, Bark, TestContext};

#[tokio::test]
async fn bark_version() {
	let ctx = TestContext::new("bark_version").await;
	let bitcoind = ctx.bitcoind("bitcoind-1").await;
	let aspd = ctx.aspd("aspd-1", &bitcoind, None).await;

	//
	let bark = ctx.bark("bark-1".to_string(), &bitcoind, &aspd).await;
	let result = bark.run(&[&"--version"]).await;

	assert!(result.starts_with("bark-client"));
}

#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/atomic-create").await;
	let bitcoind = ctx.bitcoind("bitcoind-1").await;
	let mut aspd = ctx.aspd("aspd-1", &bitcoind, None).await;

	// Create a bark defines the folder
	let _  = ctx.try_bark("bark_ok", &bitcoind, &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_ok").as_path()));

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.try_bark("bark_twice", &bitcoind, &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	let _ = ctx.try_bark("bark_twice", &bitcoind, &aspd).await.expect_err("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	// We stop the asp
	// This ensures that clients cannot be created
	aspd.stop().await.unwrap();
	let _ = ctx.try_bark("bark_fails", &bitcoind, &aspd).await.expect_err("Cannot create bark if asp is not available");
	assert!(!std::path::Path::is_dir(ctx.datadir.join("bark_fails").as_path()));
}

#[tokio::test]
async fn onboard_bark() {
	let ctx = TestContext::new("bark/onboard_bark").await;
	let bitcoind = ctx.bitcoind("bitcoind-1").await;
	let aspd = ctx.aspd("aspd-1", &bitcoind, None).await;
	let bark = ctx.bark("bark-1".to_string(), &bitcoind, &aspd).await;

	// Generate initial funds
	bitcoind.generate(101).await;

	// Get the bark-address and fund it
	bitcoind.fund_bark(&bark, Amount::from_sat(100_000)).await;
	bark.onboard(Amount::from_sat(90_000)).await;

	// TODO: Verify the onboarded balance
	// The current cli only provides logs in stdout. This is to annoying
	let _ = bark.run(["balance"]).await;
}

#[tokio::test]
async fn multiple_round_payments() {
	#[cfg(not(feature = "slow_test"))]
	const N: usize = 8;
	#[cfg(feature = "slow_test")]
	const N: usize = 74; // this is the limit with this nb_round_nonces

	info!("Running multiple_round_test with N set to {}", N);

	// Initialize the test
	let ctx = TestContext::new("bark/multiple_round_payments").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd_cfg = AspdConfig {
		round_interval: Duration::from_millis(2_000),
		round_submit_time: Duration::from_millis(100 * N as u64),
		round_sign_time: Duration::from_millis(1000 * N as u64),
		nb_round_nonces: 200,
		..ctx.aspd_default_cfg("aspd", &bitcoind, None).await
	};
	let aspd = ctx.aspd_with_cfg("aspd", aspd_cfg).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let (barks, pks) = {
		let mut barks = Vec::new();
		let mut pks = Vec::new();
		for i in 0..N {
			let b = ctx.bark(format!("bark{}", i), &bitcoind, &aspd).await;
			// Provide onchain funds
			bitcoind.fund_bark(&b, Amount::from_sat(90_000)).await;
			if i % 24 == 0 {
				bitcoind.generate(1).await;
			}
			pks.push(b.vtxo_pubkey().await);
			barks.push(b);
		}
		(barks, pks)
	};

	for chunk in barks.chunks(20) { // 25 sometimes failed..
		futures::future::join_all(chunk.iter().map(|b| {
			b.onboard(Amount::from_sat(80_000))
		})).await;
		bitcoind.generate(1).await;
	}

	let pks_shifted = pks.iter().chain(pks.iter()).skip(1).cloned().take(N).collect::<Vec<_>>();
	//TODO(stevenroose) need to find a way to ensure that all these happen in the same round
	futures::future::join_all(barks.iter().zip(pks_shifted).map(|(b, pk)| {
		b.send_round(pk, Amount::from_sat(500))
	})).await;
}

#[tokio::test]
async fn oor() {
	// Initialize the test
	let ctx = TestContext::new("bark/oor").await;
	let bitcoind = ctx.bitcoind("bitcoind-1").await;
	let aspd = ctx.aspd("aspd-1", &bitcoind, None).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark1, Amount::from_sat(90_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(5_000)).await;
	bark1.onboard(Amount::from_sat(80_000)).await;

	let pk2 = bark2.vtxo_pubkey().await;
	bark1.send_oor(pk2, Amount::from_sat(20_000)).await;

	assert_eq!(58_035, bark1.offchain_balance().await.to_sat());
	assert_eq!(20_000, bark2.offchain_balance().await.to_sat());
}

#[tokio::test]
async fn refresh() {
	// Initialize the test
	let ctx = TestContext::new("bark/refresh").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;
	bitcoind.fund_bark(&bark1, Amount::from_sat(1_000_000)).await;
	bitcoind.fund_bark(&bark2, Amount::from_sat(1_000_000)).await;
	bark1.onboard(Amount::from_sat(800_000)).await;
	bark2.onboard(Amount::from_sat(800_000)).await;

	// We want bark2 to have an onboard, round and oor vtxo
	let pk1 = bark1.vtxo_pubkey().await;
	let pk2 = bark2.vtxo_pubkey().await;
	bark2.send_round(&pk1, Amount::from_sat(20_000)).await; // generates change
	bark1.send_round(&pk2, Amount::from_sat(20_000)).await;
	bark1.send_oor(&pk2, Amount::from_sat(20_000)).await;
	bark2.onboard(Amount::from_sat(20_000)).await;

	assert_eq!(4, bark2.vtxos().await.len());
	bark2.refresh_all().await;
	assert_eq!(1, bark2.vtxos().await.len());
}

#[tokio::test]
async fn offboard_all() {
	// Initialize the test
	let ctx = TestContext::new("bark/offboard-all").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;
	let bark2 = ctx.bark("bark2".to_string(), &bitcoind, &aspd).await;

	bitcoind
		.fund_bark(&bark1, Amount::from_sat(1_000_000))
		.await;
	bark1.onboard(Amount::from_sat(800_000)).await;

	bitcoind
		.fund_bark(&bark2, Amount::from_sat(1_000_000))
		.await;

	// We want bark2 to have an onboard, round and oor vtxo
	let pk2 = bark2.vtxo_pubkey().await;
	bark2.onboard(Amount::from_sat(20_000)).await;
	bark1.send_round(&pk2, Amount::from_sat(20_000)).await;
	bark1.send_oor(&pk2, Amount::from_sat(20_000)).await;

	let address = bitcoind.get_new_address();

	assert_eq!(3, bark2.vtxos().await.len());
	bark2.offboard_all(address.clone()).await;

	// We check that all vtxos have been offboarded
	assert_eq!(0, bark2.vtxos().await.len());
	// We check that provided address received the coins
	bitcoind.generate(1).await;
	let balance = bitcoind.get_received_by_address(&address);
	assert_eq!(balance, Amount::from_sat(59100));
}

/// Util to get deterministically sorted VTXOs. Only works if VTXO amounts are strictly different
async fn get_sorted_vtxos(bark: &Bark) -> Vec<VtxoInfo> {
	let mut vtxos = bark.vtxos().await;
	vtxos.sort_by(|a, b| a.amount.cmp(&b.amount));
	vtxos
}

#[tokio::test]
async fn offboard_vtxos() {
	// Initialize the test
	let ctx = TestContext::new("bark/offboard-vtxos").await;
	let bitcoind = ctx.bitcoind("bitcoind").await;
	let aspd = ctx.aspd("aspd", &bitcoind, None).await;

	// Fund the asp
	bitcoind.generate(106).await;
	bitcoind.fund_aspd(&aspd, Amount::from_int_btc(10)).await;

	// Fund a client
	let bark1 = ctx.bark("bark1".to_string(), &bitcoind, &aspd).await;

	bitcoind
		.fund_bark(&bark1, Amount::from_sat(1_000_000))
		.await;
	bark1.onboard(Amount::from_sat(200_000)).await;
	bark1.onboard(Amount::from_sat(300_000)).await;
	bark1.onboard(Amount::from_sat(400_000)).await;

	let (first_vtxo, second_vtxo, third_vtxo) = {
		let vtxos = get_sorted_vtxos(&bark1).await;
		(vtxos[0].id, vtxos[1].id, vtxos[2].id)
	};

	let address = bitcoind.get_new_address();

	assert_eq!(3, bark1.vtxos().await.len());
	bark1.offboard_vtxo(second_vtxo, address.clone()).await;

	// We check that only selected vtxo has been touched
	let new_vtxos = get_sorted_vtxos(&bark1)
		.await
		.into_iter()
		.map(|vtxo| vtxo.id)
		.collect::<Vec<_>>();
	assert_eq!(vec![first_vtxo, third_vtxo], new_vtxos);
	// We check that provided address received the coins
	bitcoind.generate(1).await;
	let balance = bitcoind.get_received_by_address(&address);
	assert_eq!(balance, Amount::from_sat(299100));
}
