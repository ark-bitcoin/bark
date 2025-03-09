

use std::str::FromStr;

use ark_testing::daemon::aspd;
use bitcoin::Address;
use bitcoincore_rpc::bitcoin::amount::Amount;
use bitcoincore_rpc::RpcApi;
use log::trace;

use bark_json::primitives::VtxoType;
use ark::vtxo::exit_spk;
use aspd_rpc as rpc;

use ark_testing::{TestContext, Bark, btc, sat};
use ark_testing::constants::ONBOARD_CONFIRMATIONS;

async fn complete_exit(bark: &Bark) {
	let mut flip = false;
	for _ in 0..20 {
		let res = bark.progress_exit().await;

		if res.done {
			return;
		}
		if let Some(height) = res.height {
			let current = bark.bitcoind().sync_client().get_block_count().unwrap();
			bark.bitcoind().generate(height as u64 - current).await;
		} else {
			flip = if flip {
				bark.bitcoind().generate(1).await;
				false
			} else {
				true
			};
		}
	}
	panic!("failed to finish unilateral exit of bark {}", bark.name());
}

#[tokio::test]
async fn simple_exit() {
	let random_addr = Address::from_str(
		"bcrt1phrqwzmu8yvudewqefjatk20lh23vqqqnn3l57l0u2m98kd3zd70sjn2kqx"
	).unwrap().assume_checked();

	// Initialize the test
	let ctx = TestContext::new("exit/simple_exit").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark1".to_string(), &aspd, sat(1_000_000)).await;
	ctx.bitcoind.generate(1).await;

	bark.onboard(sat(500_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

	bark.refresh_all().await;
	let vtxo = &bark.vtxos().await[0];

	aspd.stop().await.unwrap();
	bark.exit_all().await;
	complete_exit(&bark).await;
	ctx.bitcoind.generate(1).await;

	// Wallet has 1_000_000 sats of funds minus fees
	assert_eq!(bark.onchain_balance().await, sat(993_210));

	// Verify exit output is considered as part of the wallets
	let utxos = bark.utxos().await;
	assert!(
		utxos.iter().any(|u| u.outpoint == vtxo.utxo && u.amount == vtxo.amount),
		"vtxo={:?}; utxos: {:?}", vtxo, utxos,
	);

	// Verify we can send exited utxo
	// Sending sats more than vtxo amount ensure we spend all available utxos
	// (vtxo output and cpfp change)
	bark.onchain_send(&random_addr, vtxo.amount + Amount::ONE_SAT).await;
}

#[tokio::test]
async fn fail_handshake() {
	//! Test that we can still access our balance and exit if server handshake fails.
	let ctx = TestContext::new("exit/fail_handshake").await;

	#[derive(Clone)]
	struct NoHandshakeProxy(rpc::ArkServiceClient<tonic::transport::Channel>);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for NoHandshakeProxy {
		fn upstream(&self) -> rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn handshake(&mut self, _: rpc::HandshakeRequest) -> Result<rpc::HandshakeResponse, tonic::Status>  {
			Ok(rpc::HandshakeResponse {
				message: Some("don't like you".into()),
				ark_info: None,
			})
		}
	}

	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(100_000)).await;

	bark.onboard(sat(90_000)).await;
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;
	ctx.bitcoind.generate(1).await;
	assert_eq!(sat(90_000), bark.offchain_balance().await);

	// now create bad proxy
	let proxy = aspd::proxy::AspdRpcProxyServer::start(NoHandshakeProxy(aspd.get_public_client().await)).await;
	bark.set_asp(&proxy.address).await;
	assert_eq!(sat(90_000), bark.offchain_balance().await);
	bark.exit_all().await;
	complete_exit(&bark).await;
	assert_eq!(bark.onchain_balance().await, sat(93_210));
}

#[tokio::test]
async fn exit_round() {
	let random_addr = Address::from_str(
		"bcrt1phrqwzmu8yvudewqefjatk20lh23vqqqnn3l57l0u2m98kd3zd70sjn2kqx"
	).unwrap().assume_checked();

	// Initialize the test
	let ctx = TestContext::new("exit/exit_round").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Fund the asp
	ctx.fund_asp(&aspd, btc(10)).await;

	// Create a few clients
	let bark1 = ctx.new_bark("bark1".to_string(), &aspd).await;
	let bark2 = ctx.new_bark("bark2".to_string(), &aspd).await;
	let bark3 = ctx.new_bark("bark3".to_string(), &aspd).await;
	let bark4 = ctx.new_bark("bark4".to_string(), &aspd).await;
	let bark5 = ctx.new_bark("bark5".to_string(), &aspd).await;
	let bark6 = ctx.new_bark("bark6".to_string(), &aspd).await;
	let bark7 = ctx.new_bark("bark7".to_string(), &aspd).await;
	let bark8 = ctx.new_bark("bark8".to_string(), &aspd).await;

	tokio::join!(
		ctx.fund_bark(&bark1, sat(1_000_000)),
		ctx.fund_bark(&bark2, sat(1_000_000)),
		ctx.fund_bark(&bark3, sat(1_000_000)),
		ctx.fund_bark(&bark4, sat(1_000_000)),
		ctx.fund_bark(&bark5, sat(1_000_000)),
		ctx.fund_bark(&bark6, sat(1_000_000)),
		ctx.fund_bark(&bark7, sat(1_000_000)),
		ctx.fund_bark(&bark8, sat(1_000_000)),
	);
	ctx.bitcoind.generate(1).await;

	tokio::join!(
		bark1.onboard(sat(500_000)),
		bark2.onboard(sat(500_000)),
		bark3.onboard(sat(500_000)),
		bark4.onboard(sat(500_000)),
		bark5.onboard(sat(500_000)),
		bark6.onboard(sat(500_000)),
		bark7.onboard(sat(500_000)),
		bark8.onboard(sat(500_000)),
	);
	ctx.bitcoind.generate(ONBOARD_CONFIRMATIONS).await;

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

	let bark1_round_vtxo = &bark1.vtxos().await[0];
	let bark2_round_vtxo = &bark2.vtxos().await[0];
	let bark3_round_vtxo = &bark3.vtxos().await[0];
	let bark4_round_vtxo = &bark4.vtxos().await[0];
	let bark5_round_vtxo = &bark5.vtxos().await[0];
	let bark6_round_vtxo = &bark6.vtxos().await[0];
	let bark7_round_vtxo = &bark7.vtxos().await[0];
	let bark8_round_vtxo = &bark8.vtxos().await[0];

	// We don't need ASP for exits.
	aspd.stop().await.unwrap();

	bark1.exit_all().await;
	bark2.exit_all().await;
	bark3.exit_all().await;
	bark4.exit_all().await;
	bark5.exit_all().await;
	bark6.exit_all().await;
	bark7.exit_all().await;
	bark8.exit_all().await;

	complete_exit(&bark1).await;
	complete_exit(&bark2).await;
	complete_exit(&bark3).await;
	complete_exit(&bark4).await;
	complete_exit(&bark5).await;
	complete_exit(&bark6).await;
	complete_exit(&bark7).await;
	complete_exit(&bark8).await;

	// All wallets have 1_000_000 sats of funds minus fees
	//
	// However, what fees are paid by which client is not fully predictable
	// This depends on the shape of the tree and the order of the exit
	//
	// We can't control the shape of the tree in the test.
	// The order of the exit is also somewhat random
	assert!(bark1.onchain_balance().await >= bark1_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark2.onchain_balance().await >= bark2_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark3.onchain_balance().await >= bark3_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark4.onchain_balance().await >= bark4_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark5.onchain_balance().await >= bark5_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark6.onchain_balance().await >= bark6_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark7.onchain_balance().await >= bark7_round_vtxo.amount + Amount::ONE_SAT);
	assert!(bark8.onchain_balance().await >= bark8_round_vtxo.amount + Amount::ONE_SAT);

	// Verify exit outputs are considered as part of the wallets
	assert!(bark1.utxos().await.iter().any(|u| u.outpoint == bark1_round_vtxo.utxo && u.amount == bark1_round_vtxo.amount));
	assert!(bark2.utxos().await.iter().any(|u| u.outpoint == bark2_round_vtxo.utxo && u.amount == bark2_round_vtxo.amount));
	assert!(bark3.utxos().await.iter().any(|u| u.outpoint == bark3_round_vtxo.utxo && u.amount == bark3_round_vtxo.amount));
	assert!(bark4.utxos().await.iter().any(|u| u.outpoint == bark4_round_vtxo.utxo && u.amount == bark4_round_vtxo.amount));
	assert!(bark5.utxos().await.iter().any(|u| u.outpoint == bark5_round_vtxo.utxo && u.amount == bark5_round_vtxo.amount));
	assert!(bark6.utxos().await.iter().any(|u| u.outpoint == bark6_round_vtxo.utxo && u.amount == bark6_round_vtxo.amount));
	assert!(bark7.utxos().await.iter().any(|u| u.outpoint == bark7_round_vtxo.utxo && u.amount == bark7_round_vtxo.amount));
	assert!(bark8.utxos().await.iter().any(|u| u.outpoint == bark8_round_vtxo.utxo && u.amount == bark8_round_vtxo.amount));

	// Verify we can send exited utxos
	// Sending sats more than vtxo amount ensure we spend all available utxos (vtxo output and cpfp change)
	bark1.onchain_send(&random_addr, bark1_round_vtxo.amount + Amount::ONE_SAT).await;
	bark2.onchain_send(&random_addr, bark2_round_vtxo.amount + Amount::ONE_SAT).await;
	bark3.onchain_send(&random_addr, bark3_round_vtxo.amount + Amount::ONE_SAT).await;
	bark4.onchain_send(&random_addr, bark4_round_vtxo.amount + Amount::ONE_SAT).await;
	bark5.onchain_send(&random_addr, bark5_round_vtxo.amount + Amount::ONE_SAT).await;
	bark6.onchain_send(&random_addr, bark6_round_vtxo.amount + Amount::ONE_SAT).await;
	bark7.onchain_send(&random_addr, bark7_round_vtxo.amount + Amount::ONE_SAT).await;
	bark8.onchain_send(&random_addr, bark8_round_vtxo.amount + Amount::ONE_SAT).await;
}

#[tokio::test]
async fn exit_vtxo() {
	let ctx = TestContext::new("exit/exit_vtxo").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	ctx.bitcoind.generate(1).await;

	bark.onboard(sat(900_000)).await;
	ctx.bitcoind.generate(15).await;
	bark.refresh_all().await;

	// By calling bark vtxos we ensure the wallet is synced
	// This ensures bark knows the vtxo exists
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have refreshed one vtxo");
	let vtxo = &vtxos[0];

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark exit and check the balance
	bark.exit_vtxo(vtxo.id).await;
	complete_exit(&bark).await;

	// Verify exit output is considered as part of the wallet
	let utxos = bark.utxos().await;
	assert_eq!(utxos.len(), 2, "We have cpfp change (spent in exit process) + exited utxo");
	assert!(utxos.iter().any(|u| u.outpoint == vtxo.utxo && u.amount == vtxo.amount));

	// Verify we can send both utxos
	bark.onchain_send(bark.get_onchain_address().await, vtxo.amount + Amount::ONE_SAT).await;
}


#[tokio::test]
async fn exit_after_onboard() {
	let random_addr = Address::from_str(
		"bcrt1phrqwzmu8yvudewqefjatk20lh23vqqqnn3l57l0u2m98kd3zd70sjn2kqx"
	).unwrap().assume_checked();

	let ctx = TestContext::new("exit/exit_after_onboard").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Fund the bark instance
	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	// Onboard funds
	bark.onboard(sat(900_000)).await;

	let onboard_vtxo = &bark.vtxos().await[0];

	// Exit unilaterally
	aspd.stop().await.unwrap();
	bark.exit_all().await;
	complete_exit(&bark).await;

	let balance = bark.onchain_balance().await;
	assert!(balance > sat(900_000), "balance: {balance}");

	// Verify exit output is considered as part of the wallet
	let utxos = bark.utxos().await;
	assert_eq!(utxos.len(), 2, "We have cpfp change (spent in exit process) + exited utxo");
	assert!(utxos.iter().any(|u| u.outpoint == onboard_vtxo.utxo && u.amount == onboard_vtxo.amount));

	// Verify we can send both utxos
	bark.onchain_send(random_addr, onboard_vtxo.amount + Amount::ONE_SAT).await;
}

#[tokio::test]
async fn exit_oor() {
	let ctx = TestContext::new("exit/exit_oor").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Bark1 will pay bark2 oor.
	// Bark2 will attempt an exit
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	ctx.bitcoind.generate(1).await;

	// Bark1 onboard funds and sends some part to bark2
	bark1.onboard(sat(900_000)).await;
	let bark2_pubkey = bark2.vtxo_pubkey().await;
	bark1.send_oor(bark2_pubkey, sat(100_000)).await;

	// By calling bark2 vtxos we ensure the wallet is synced
	// This ensures bark2 knows the vtxo exists
	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have received one vtxo");
	let oor_vtxo = &vtxos[0];
	assert_eq!(oor_vtxo.vtxo_type, VtxoType::Arkoor);

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark2 exit and check the balance
	// It should be FUND_AMOUNT + VTXO_AMOUNT - fees
	bark2.exit_all().await;
	complete_exit(&bark2).await;
	assert_eq!(bark2.onchain_balance().await, sat(1_089_521));

	// Verify exit output is considered as part of the wallet
	let utxos = bark2.utxos().await;
	assert_eq!(utxos.len(), 2, "We have cpfp change (spent in exit process) + exited utxo");
	assert!(utxos.iter().any(|u| u.outpoint == oor_vtxo.utxo && u.amount == oor_vtxo.amount));

	// Verify we can send both utxos
	bark2.onchain_send(bark1.get_onchain_address().await, oor_vtxo.amount + Amount::ONE_SAT).await;
}

#[tokio::test]
async fn double_exit_call() {
	let ctx = TestContext::new("exit/double_exit_call").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.onboard(sat(800_000)).await;

	// refresh vtxo
	bark1.onboard(sat(200_000)).await;
	ctx.bitcoind.generate(12).await;
	bark1.refresh_all().await;

	// onboard vtxo
	bark1.onboard(sat(300_000)).await;
	ctx.bitcoind.generate(12).await;

	// oor vtxo
	bark2.send_oor(&bark1.vtxo_pubkey().await, sat(330_000)).await;



	let vtxos = bark1.vtxos().await;

	bark1.exit_all().await;
	complete_exit(&bark1).await;
	assert_eq!(bark1.onchain_balance().await, sat(1_305_941));

	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 7);

	let last_moves = &movements[0..=2];
	assert!(
		vtxos.iter().all(|v| last_moves.iter().any(|m|
			m.spends.first().unwrap().id == v.id &&
			m.destination.clone().unwrap() ==
				exit_spk(v.user_pubkey, v.asp_pubkey, v.exit_delta).to_string()
		)), "each exited vtxo should be linked to a movement with exit_spk as destination"
	);
	assert_eq!(bark1.vtxos().await.len(), 0, "all vtxos should be marked as spent");

	// create a new vtxo to exit
	bark2.send_oor(bark1.vtxo_pubkey().await, sat(145_000)).await;
	let vtxos = bark1.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	let vtxo = vtxos.first().unwrap();

	bark1.exit_all().await;
	complete_exit(&bark1).await;

	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 9);

	// check we only exited last vtxo
	let last_move = movements.first().unwrap();
	assert_eq!(last_move.spends.len(), 1, "we should only exit last spendable vtxo");
	assert_eq!(last_move.spends.first().unwrap().id, vtxo.id);
	let exit_spk = exit_spk(vtxo.user_pubkey, vtxo.asp_pubkey, vtxo.exit_delta).to_string();
	assert_eq!(last_move.destination.clone().unwrap(), exit_spk, "movement destination should be exit_spk");
	assert_eq!(bark1.vtxos().await.len(), 0, "vtxo should be marked as spent");

	bark1.exit_all().await;
	complete_exit(&bark1).await;
	assert_eq!(bark1.list_movements().await.len(), 9, "should not create new movement when no new vtxo to exit");
}

#[tokio::test]
async fn exit_bolt11_change() {
	let ctx = TestContext::new("exit/exit_bolt11_change").await;

	// Start 2 lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	trace!("Funding all lightning-nodes");
	ctx.fund_lightning(&lightningd_1, btc(10)).await;
	ctx.bitcoind.generate(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	// TODO: find a way how to remove this sleep
	// maybe: let ctx.bitcoind wait for channel funding transaction
	// without the sleep we get infinite 'Waiting for gossip...'
	tokio::time::sleep(std::time::Duration::from_millis(8_000)).await;
	ctx.bitcoind.generate(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, btc(7)).await;

	let onboard_amount = btc(5);
	bark_1.onboard(onboard_amount).await;
	ctx.bitcoind.generate(6).await;

	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	assert_eq!(bark_1.offchain_balance().await, onboard_amount);
	bark_1.send_bolt11(invoice, None).await;
	assert_eq!(bark_1.offchain_balance().await, sat(299999320));

	// We try to perform an exit for ln payment change
	let vtxo = &bark_1.vtxos().await[0];

	aspd_1.stop().await.unwrap();
	bark_1.exit_all().await;
	complete_exit(&bark_1).await;

	assert_eq!(bark_1.offchain_balance().await, Amount::ZERO);
	assert!(bark_1.onchain_balance().await >= vtxo.amount + Amount::ONE_SAT);
	assert!(bark_1.utxos().await.iter().any(|u| u.outpoint == vtxo.utxo && u.amount == vtxo.amount));
}
