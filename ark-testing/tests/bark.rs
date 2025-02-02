#[macro_use]
extern crate log;

use std::fs;
use std::io::{self, BufRead};
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool};
use std::time::Duration;

use ark_testing::util::FutureExt;
use aspd_log::{MissingForfeits, RestartMissingForfeits, RoundUserVtxoNotAllowed};
use bitcoin::key::Keypair;
use bitcoincore_rpc::{bitcoin::amount::Amount, RpcApi};

use ark::{ArkoorVtxo, Vtxo};
use aspd_rpc as rpc;
use ark_testing::setup::{setup_asp_funded, setup_full, setup_simple};
use ark_testing::{AspdConfig, TestContext};
use ark_testing::daemon::aspd;

const OFFBOARD_FEES: Amount = Amount::from_sat(900);

#[tokio::test]
async fn bark_version() {
	let setup = setup_simple("bark/bark_version").await;

	let result = setup.bark1.run(&[&"--version"]).await;

	assert!(result.starts_with("bark-client"));
}

#[tokio::test]
async fn bark_create_is_atomic() {
	let ctx = TestContext::new("bark/bark_create_is_atomic").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Create a bark defines the folder
	let _  = ctx.try_new_bark("bark_ok", &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_ok").as_path()));

	// You can't create a bark twice
	// If you want to overwrite the folder you need force
	let _ = ctx.try_new_bark("bark_twice", &aspd).await.expect("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	let _ = ctx.try_new_bark("bark_twice", &aspd).await.expect_err("Can create bark");
	assert!(std::path::Path::is_dir(ctx.datadir.join("bark_twice").as_path()));

	// We stop the asp
	// This ensures that clients cannot be created
	aspd.stop().await.unwrap();
	let _ = ctx.try_new_bark("bark_fails", &aspd).await.expect_err("Cannot create bark if asp is not available");
	assert!(!std::path::Path::is_dir(ctx.datadir.join("bark_fails").as_path()));
}

#[tokio::test]
async fn onboard_bark() {
	const ONBOARD_AMOUNT: u64 = 90_000;
	let setup = setup_simple("bark/onboard_bark").await;

	// Get the bark-address and fund it
	setup.context.fund_bark(&setup.bark1, Amount::from_sat(100_000)).await;

	setup.bark1.onboard(Amount::from_sat(ONBOARD_AMOUNT)).await;

	assert_eq!(Amount::from_sat(ONBOARD_AMOUNT), setup.bark1.offchain_balance().await);
}

#[tokio::test]
async fn onboard_all_bark() {
	let setup = setup_simple("bark/onboard_all_bark").await;

	// Get the bark-address and fund it
	setup.context.fund_bark(&setup.bark1, Amount::from_sat(100_000)).await;
	assert_eq!(setup.bark1.onchain_balance().await, Amount::from_sat(100_000));

	let onboard_txid = setup.bark1.onboard_all().await.funding_txid;

	// Check that we emptied our on-chain balance
	assert_eq!(setup.bark1.onchain_balance().await, Amount::ZERO);

	// Check if the onboarding tx's output value is the same as our off-chain balance
	let sync_client = setup.bark1.bitcoind().sync_client();
	let onboard_tx = sync_client.get_raw_transaction(&onboard_txid, None).unwrap();
	assert_eq!(setup.bark1.offchain_balance().await, onboard_tx.output.last().unwrap().value - ark::onboard::onboard_surplus());
	assert_eq!(setup.bark1.onchain_balance().await, Amount::ZERO);
}

#[tokio::test]
async fn list_utxos() {
	let setup = setup_full("bark/list_utxos").await;

	let bark1_address = setup.bark1.get_onchain_address().await;
	setup.bark1.offboard_all(bark1_address.clone()).await;

	// If this test gets flaky, try add some delay here:
	// tokio::time::sleep(Duration::from_millis(500)).await;

	let utxos = setup.bark1.utxos().await;

	assert_eq!(2, utxos.len());
	// onboard change utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 496_254));
	// offboard utxo
	assert!(utxos.iter().any(|u| u.amount.to_sat() == 828_900));
}

#[tokio::test]
async fn list_vtxos() {
	let setup = setup_full("bark/list_vtxos").await;

	let vtxos = setup.bark1.vtxos().await;
	assert_eq!(3, vtxos.len());
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 200_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 300_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 330_000));

	// Should have the same behaviour when ASP is offline
	setup.aspd.stop().await.unwrap();

	let vtxos = setup.bark1.vtxos().await;
	assert_eq!(3, vtxos.len());
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 200_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 300_000));
	assert!(vtxos.iter().any(|v| v.amount.to_sat() == 330_000));
}

#[tokio::test]
async fn large_round() {
	let ctx = TestContext::new("bark/large_round").await;
	#[cfg(not(feature = "slow_test"))]
	const N: usize = 9;
	#[cfg(feature = "slow_test")]
	const N: usize = 74;

	info!("Running multiple_round_test with N set to {}", N);

	// Initialize the test
	let aspd_cfg = AspdConfig {
		round_interval: Duration::from_millis(2_000),
		round_submit_time: Duration::from_millis(100 * N as u64),
		round_sign_time: Duration::from_millis(1000 * N as u64),
		nb_round_nonces: 200,
		..ctx.aspd_default_cfg("aspd", None).await
	};
	let aspd = ctx.new_aspd_with_cfg("aspd", aspd_cfg).await;

	// Fund the asp
	ctx.fund_asp(&aspd, Amount::from_int_btc(10)).await;

	// Create a few clients
	let (barks, pks) = {
		let mut barks = Vec::new();
		let mut pks = Vec::new();
		// TODO: This might be parallelized
		// Currently, each creation of bark is waiting, in sequence, for its funding transaction
		for i in 0..N {
			let b = ctx.new_bark_with_funds(format!("bark{}", i), &aspd, Amount::from_sat(90_000)).await;
			pks.push(b.vtxo_pubkey().await);
			barks.push(b);
		}
		(barks, pks)
	};

	ctx.bitcoind.generate(1).await;

	// Fund and onboard all clients.
	for chunk in barks.chunks(20) {
		futures::future::join_all(chunk.iter().map(|b| async {
			b.onboard(Amount::from_sat(80_000)).await;
		})).await;
	}

	ctx.bitcoind.generate(1).await;

	// Refresh all vtxos
	let pks_shifted = pks.iter().chain(pks.iter()).skip(1).cloned().take(N).collect::<Vec<_>>();
	//TODO(stevenroose) need to find a way to ensure that all these happen in the same round
	futures::future::join_all(barks.iter().zip(pks_shifted).map(|(b, _pk)| {
		b.refresh_all()
	})).await;
}

#[tokio::test]
async fn oor() {
	// Initialize the test
	let setup = setup_asp_funded("bark/oor").await;

	// Fund clients
	setup.context.fund_bark(&setup.bark1, Amount::from_sat(90_000)).await;
	setup.context.fund_bark(&setup.bark2, Amount::from_sat(5_000)).await;
	setup.context.bitcoind.generate(1).await;
	setup.bark1.onboard(Amount::from_sat(80_000)).await;

	let pk2 = setup.bark2.vtxo_pubkey().await;
	setup.bark1.send_oor(pk2, Amount::from_sat(20_000)).await;

	assert_eq!(58_035, setup.bark1.offchain_balance().await.to_sat());
	assert_eq!(20_000, setup.bark2.offchain_balance().await.to_sat());
}

#[tokio::test]
async fn refresh() {
	let setup = setup_asp_funded("bark/refresh").await;

	// Fund clients
	setup.context.fund_bark(&setup.bark1, Amount::from_sat(1_000_000)).await;
	setup.context.fund_bark(&setup.bark2, Amount::from_sat(1_000_000)).await;
	setup.context.bitcoind.generate(1).await;
	setup.bark1.onboard(Amount::from_sat(800_000)).await;
	setup.bark2.onboard(Amount::from_sat(800_000)).await;

	// We want bark2 to have a refresh, onboard, round and oor vtxo
	let pk1 = setup.bark1.vtxo_pubkey().await;
	let pk2 = setup.bark2.vtxo_pubkey().await;
	setup.bark2.send_oor(&pk1, Amount::from_sat(20_000)).await; // generates change
	setup.bark1.refresh_all().await;
	setup.bark1.send_oor(&pk2, Amount::from_sat(20_000)).await;
	setup.bark2.onboard(Amount::from_sat(20_000)).await;

	assert_eq!(3, setup.bark2.vtxos().await.len());
	setup.bark2.refresh_all().await;
	assert_eq!(1, setup.bark2.vtxos().await.len());
}

#[tokio::test]
async fn refresh_counterparty() {
	let setup = setup_full("bark/refresh_counterparty").await;

	let (oor_vtxo, others): (Vec<_>, Vec<_>) = setup.bark1.vtxos().await
		.into_iter()
		.partition(|v| v.amount == Amount::from_sat(330_000));

	setup.bark1.refresh_counterparty().await;

	let vtxos = setup.bark1.vtxos().await;
	// there should still be 3 vtxos
	assert_eq!(3, vtxos.len());
	// received oor vtxo should be refreshed
	assert!(!vtxos.iter().any(|v| v.id == oor_vtxo.first().unwrap().id));
	// others should remain untouched
	assert!(others.iter().all(|o| vtxos.iter().any(|v| v.id == o.id)));
}

#[tokio::test]
async fn compute_balance() {
	let setup = setup_full("bark/compute_balance").await;

	let balance = setup.bark1.offchain_balance().await;
	assert_eq!(balance, Amount::from_sat(830_000));

	// Should have the same behaviour when ASP is offline
	setup.aspd.stop().await.unwrap();

	let balance = setup.bark1.offchain_balance().await;
	assert_eq!(balance, Amount::from_sat(830_000));
}

#[tokio::test]
async fn list_movements() {
	// Initialize the test
	let ctx = TestContext::new("bark/list_movements").await;

	let aspd = ctx.new_aspd_with_funds("aspd", None, Amount::from_int_btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, Amount::from_sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, Amount::from_sat(1_000_000)).await;

	ctx.bitcoind.generate(1).await;

	bark2.onboard(Amount::from_sat(800_000)).await;

	// onboard vtxo
	bark1.onboard(Amount::from_sat(300_000)).await;
	let payments = bark1.list_movements().await;
	assert_eq!(payments.len(), 1);
	assert_eq!(payments[0].spends.len(), 0);
	assert_eq!(payments[0].receives[0].amount, Amount::from_sat(300_000));
	assert_eq!(payments[0].fees.to_sat(), 0);
	assert!(payments[0].destination.is_none());

	// oor change
	bark1.send_oor(&bark2.vtxo_pubkey().await, Amount::from_sat(150_000)).await;
	let payments = bark1.list_movements().await;
	assert_eq!(payments.len(), 2);
	assert_eq!(payments[0].spends[0].amount, Amount::from_sat(300_000));
	assert_eq!(payments[0].receives[0].amount, Amount::from_sat(148_035));
	assert_eq!(payments[0].fees.to_sat(), 1965);
	assert!(payments[0].destination.is_some());

	// refresh vtxos
	bark1.refresh_all().await;
	let payments = bark1.list_movements().await;
	assert_eq!(payments.len(), 3);
	assert_eq!(payments[0].spends[0].amount, Amount::from_sat(148_035));
	assert_eq!(payments[0].receives[0].amount, Amount::from_sat(148_035));
	assert_eq!(payments[0].fees.to_sat(), 0);
	assert!(payments[0].destination.is_none());

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, Amount::from_sat(330_000)).await;
	let payments = bark1.list_movements().await;
	assert_eq!(payments.len(), 4);
	assert_eq!(payments[0].spends.len(), 0);
	assert_eq!(payments[0].receives[0].amount, Amount::from_sat(330_000));
	assert_eq!(payments[0].fees.to_sat(), 0);
	assert!(payments[0].destination.is_none());
}

#[tokio::test]
async fn multiple_spends_in_payment() {
	// Initialize the test
	let ctx = TestContext::new("bark/multiple_spends_in_payment").await;

	let aspd = ctx.new_aspd_with_funds("aspd", None, Amount::from_int_btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &aspd, Amount::from_sat(1_000_000)).await;

	ctx.bitcoind.generate(1).await;

	bark1.onboard(Amount::from_sat(100_000)).await;
	bark1.onboard(Amount::from_sat(200_000)).await;
	bark1.onboard(Amount::from_sat(300_000)).await;

	// refresh vtxos
	bark1.refresh_all().await;
	let payments = bark1.list_movements().await;
	assert_eq!(payments[0].spends.len(), 3);
	assert_eq!(payments[0].spends[0].amount, Amount::from_sat(100_000));
	assert_eq!(payments[0].spends[1].amount, Amount::from_sat(200_000));
	assert_eq!(payments[0].spends[2].amount, Amount::from_sat(300_000));
	assert_eq!(payments[0].receives[0].amount, Amount::from_sat(600_000));
	assert_eq!(payments[0].fees.to_sat(), 0);
}

#[tokio::test]
async fn offboard_all() {
	let setup = setup_full("bark/offboard_all").await;

	let address = setup.context.bitcoind.get_new_address();

	let init_balance = setup.bark1.offchain_balance().await;
	assert_eq!(init_balance, Amount::from_sat(830_000));

	setup.bark1.offboard_all(address.clone()).await;

	// We check that all vtxos have been offboarded
	assert_eq!(Amount::ZERO, setup.bark1.offchain_balance().await);

	let movements = setup.bark1.list_movements().await;
	let offb_movement = movements.first().unwrap();
	assert_eq!(offb_movement.spends.len(), 3, "all offboard vtxos should be in movement");
	assert_eq!(offb_movement.destination, Some(address.script_pubkey().to_string()), "destination should be correct");

	// We check that provided address received the coins
	setup.context.bitcoind.generate(1).await;
	let balance = setup.context.bitcoind.get_received_by_address(&address);
	assert_eq!(balance, init_balance - OFFBOARD_FEES);
}

#[tokio::test]
async fn offboard_vtxos() {
	let setup = setup_full("bark/offboard_vtxos").await;

	let vtxos = setup.bark1.vtxos().await;
	assert_eq!(3, vtxos.len());

	let address = setup.context.bitcoind.get_new_address();
	let vtxo_to_offboard = &vtxos[1];

	setup.bark1.offboard_vtxo(vtxo_to_offboard.id, address.clone()).await;

	// We check that only selected vtxo has been touched
	let updated_vtxos = setup.bark1.vtxos().await
		.into_iter()
		.map(|vtxo| vtxo.id)
		.collect::<Vec<_>>();

	assert!(updated_vtxos.contains(&vtxos[0].id));
	assert!(updated_vtxos.contains(&vtxos[2].id));

	let movements = setup.bark1.list_movements().await;
	let offb_movement = movements.first().unwrap();
	assert_eq!(offb_movement.spends.len(), 1, "only provided vtxo should be offboarded");
	assert_eq!(offb_movement.spends[0].id, vtxo_to_offboard.id, "only provided vtxo should be offboarded");
	assert_eq!(offb_movement.destination, Some(address.script_pubkey().to_string()), "destination should be correct");

	// We check that provided address received the coins
	setup.context.bitcoind.generate(1).await;
	let balance = setup.context.bitcoind.get_received_by_address(&address);
	assert_eq!(balance, vtxo_to_offboard.amount - OFFBOARD_FEES);
}

#[tokio::test]
async fn drop_vtxos() {
	// Initialize the test
	let setup = setup_full("bark/drop_vtxos").await;

	setup.bark1.drop_vtxos().await;
	let balance = setup.bark1.offchain_balance_no_sync().await;

	assert_eq!(balance, Amount::ZERO);
}

#[tokio::test]
async fn reject_oor_with_bad_signature() {
	#[derive(Clone)]
	struct InvalidSigProxy(rpc::ArkServiceClient<tonic::transport::Channel>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for InvalidSigProxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn empty_oor_mailbox(&mut self, req: rpc::OorVtxosRequest) -> Result<rpc::OorVtxosResponse, tonic::Status>  {
			info!("proxy handling oor request");
			let response = self.upstream().empty_oor_mailbox(req).await?;
			info!("proxy received real response");

			let keypair = Keypair::new(&ark::util::SECP, &mut rand::thread_rng());
			let (inputs, output_specs, point) = match
				Vtxo::decode(&response.into_inner().vtxos[0]).unwrap() {
					Vtxo::Arkoor(v) => (v.inputs, v.output_specs, v.point),
					_ => panic!("expect oor vtxo")
				};

			let mut fake_sigs = Vec::with_capacity(inputs.len());

			let sighashes = ark::oor::oor_sighashes(
				&inputs, &ark::oor::unsigned_oor_transaction(&inputs, &output_specs),
			);
			for sighash in sighashes.into_iter() {
				let sig = ark::util::SECP.sign_schnorr(&sighash.into(), &keypair);
				fake_sigs.push(sig);
			}

			let vtxo = Vtxo::Arkoor(ArkoorVtxo { inputs, signatures: fake_sigs, output_specs, point });

			Ok(rpc::OorVtxosResponse {
				vtxos: vec![vtxo.encode()]
			})
		}
	}

	// Initialize the test
	let setup = setup_full("bark/reject_oor_with_bad_signature").await;

	// create a proxy to return an arkoor with invalid signatures
	let proxy = aspd::proxy::AspdRpcProxyServer::start(InvalidSigProxy(setup.aspd.get_public_client().await)).await;

	// create a third wallet to receive the invalid arkoor
	let bark3 = setup.context.new_bark("bark3".to_string(), &proxy.address).await;

	setup.bark2.send_oor(bark3.vtxo_pubkey().await, Amount::from_sat(10_000)).await;

	// we should drop invalid arkoors
	assert_eq!(bark3.vtxos().await.len(), 0);

	// check that we saw a log
	assert!(io::BufReader::new(fs::File::open(bark3.command_log_file()).unwrap()).lines().any(|line| {
		line.unwrap().contains("Could not validate OOR signature, dropping vtxo. signature failed verification")
	}));
}

#[tokio::test]
async fn second_round_attempt() {
	//! test that we can recover from an error in the round

	/// This proxy will drop the very first request to provide_forfeit_signatures.
	#[derive(Clone)]
	struct Proxy(rpc::ArkServiceClient<tonic::transport::Channel>, Arc<AtomicBool>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn provide_forfeit_signatures(
			&mut self,
			req: rpc::ForfeitSignaturesRequest,
		) -> Result<rpc::Empty, tonic::Status> {
			if self.1.swap(false, atomic::Ordering::Relaxed) {
				Ok(rpc::Empty {})
			} else {
				Ok(self.0.provide_forfeit_signatures(req).await?.into_inner())
			}
		}
	}

	let ctx = TestContext::new("bark/second_round_attempt").await;
	let aspd = ctx.new_aspd_with_cfg("aspd", AspdConfig {
		round_interval: Duration::from_secs(3600),
		..ctx.aspd_default_cfg("aspd", None).await
	}).await;
	ctx.fund_asp(&aspd, Amount::from_int_btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1".to_string(), &aspd, Amount::from_sat(1_000_000)).await;
	bark1.onboard(Amount::from_sat(800_000)).await;

	let proxy = Proxy(aspd.get_public_client().await, Arc::new(AtomicBool::new(true)));
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

	let bark2 = ctx.new_bark("bark2".to_string(), &proxy.address).await;
	bark1.send_oor(bark2.vtxo_pubkey().await, Amount::from_sat(200_000)).await;
	let bark2_vtxo = bark2.vtxos().await.get(0).expect("should have 1 vtxo").id;

	let mut log_missing_forfeits = aspd.subscribe_log::<MissingForfeits>().await;
	let mut log_not_allowed = aspd.subscribe_log::<RoundUserVtxoNotAllowed>().await;

	let res1 = tokio::spawn(async move { bark1.refresh_all().await });
	let res2 = tokio::spawn(async move { bark2.refresh_all().await });
	tokio::time::sleep(Duration::from_millis(500)).await;
	aspd.trigger_round().await;
	aspd.wait_for_log::<RestartMissingForfeits>().await;
	res1.await.unwrap();
	// check that bark2 was kicked
	assert_eq!(log_missing_forfeits.recv().fast().await.unwrap().input, bark2_vtxo);
	assert_eq!(log_not_allowed.recv().fast().await.unwrap().vtxo, bark2_vtxo);

	// bark2 is kicked out of the first round, so we need to start another one
	aspd.trigger_round().await;
	res2.await.unwrap();
}

