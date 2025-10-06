

use ark_testing::exit::complete_exit;
use bitcoin::{Address, Amount, FeeRate};
use bitcoin::params::Params;
use futures::FutureExt;
use log::trace;
use rand::random;

use ark::vtxo::exit_taproot;
use bark_json::exit::ExitState;
use bark_json::exit::states::ExitStartState;
use bitcoin_ext::TaprootSpendInfoExt;
use server_rpc::protos;

use ark_testing::{btc, sat, Bark, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind;

#[tokio::test]
async fn simple_exit() {
	// Initialize the test
	let ctx = TestContext::new("exit/simple_exit").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark1".to_string(), &srv, sat(1_000_000)).await;
	ctx.generate_blocks(1).await;

	bark.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	srv.stop().await.unwrap();
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Wallet has 1_000_000 sats of funds minus fees
	assert_eq!(bark.onchain_balance().await, sat(997_201));
}

#[tokio::test]
async fn exit_round() {
	// Initialize the test
	let ctx = TestContext::new("exit/exit_round").await;
	let srv = ctx.new_captaind("server", None).await;

	// Fund the server
	ctx.fund_captaind(&srv, btc(10)).await;

	// Create a few clients
	let create_bark = |name: &str| ctx.try_new_bark_with_create_args::<String>(
		name.to_string(),
		&srv,
		Some(FeeRate::from_sat_per_kwu(250 + random::<u64>() % 24_750)), // 1 to 100 sats/vB
		[],
	);
	let bark1 = create_bark("bark1").await.unwrap();
	let bark2 = create_bark("bark2").await.unwrap();
	let bark3 = create_bark("bark3").await.unwrap();
	let bark4 = create_bark("bark4").await.unwrap();
	let bark5 = create_bark("bark5").await.unwrap();
	let bark6 = create_bark("bark6").await.unwrap();
	let bark7 = create_bark("bark7").await.unwrap();
	let bark8 = create_bark("bark8").await.unwrap();

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
	ctx.generate_blocks(1).await;

	tokio::join!(
		bark1.board(sat(500_000)),
		bark2.board(sat(500_000)),
		bark3.board(sat(500_000)),
		bark4.board(sat(500_000)),
		bark5.board(sat(500_000)),
		bark6.board(sat(500_000)),
		bark7.board(sat(500_000)),
		bark8.board(sat(500_000)),
	);
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

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
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let bark1_round_vtxo = &bark1.vtxos().await[0];
	let bark2_round_vtxo = &bark2.vtxos().await[0];
	let bark3_round_vtxo = &bark3.vtxos().await[0];
	let bark4_round_vtxo = &bark4.vtxos().await[0];
	let bark5_round_vtxo = &bark5.vtxos().await[0];
	let bark6_round_vtxo = &bark6.vtxos().await[0];
	let bark7_round_vtxo = &bark7.vtxos().await[0];
	let bark8_round_vtxo = &bark8.vtxos().await[0];

	// We don't need server for exits.
	srv.stop().await.unwrap();

	tokio::join!(
		bark1.start_exit_all().then(|_| async { complete_exit(&ctx, &bark1).await }),
		bark2.start_exit_all().then(|_| async { complete_exit(&ctx, &bark2).await }),
		bark3.start_exit_all().then(|_| async { complete_exit(&ctx, &bark3).await }),
		bark4.start_exit_all().then(|_| async { complete_exit(&ctx, &bark4).await }),
		bark5.start_exit_all().then(|_| async { complete_exit(&ctx, &bark5).await }),
		bark6.start_exit_all().then(|_| async { complete_exit(&ctx, &bark6).await }),
		bark7.start_exit_all().then(|_| async { complete_exit(&ctx, &bark7).await }),
		bark8.start_exit_all().then(|_| async { complete_exit(&ctx, &bark8).await }),
	);

	tokio::join!(
		bark1.claim_all_exits(bark1.get_onchain_address().await),
		bark2.claim_all_exits(bark2.get_onchain_address().await),
		bark3.claim_all_exits(bark3.get_onchain_address().await),
		bark4.claim_all_exits(bark4.get_onchain_address().await),
		bark5.claim_all_exits(bark5.get_onchain_address().await),
		bark6.claim_all_exits(bark6.get_onchain_address().await),
		bark7.claim_all_exits(bark7.get_onchain_address().await),
		bark8.claim_all_exits(bark8.get_onchain_address().await),
	);
	ctx.generate_blocks(1).await;

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
}

#[tokio::test]
async fn exit_vtxo() {
	let ctx = TestContext::new("exit/exit_vtxo").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// By calling bark vtxos we ensure the wallet is synced
	// This ensures bark knows the vtxo exists
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have refreshed one vtxo");
	let vtxo = &vtxos[0];

	// We stop the server
	srv.stop().await.unwrap();

	// Make bark exit and check the balance
	bark.start_exit_vtxos([vtxo.id]).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark.onchain_balance().await, sat(997_201));
}

#[tokio::test]
async fn exit_and_send_vtxo() {
	let ctx = TestContext::new("exit/exit_and_send_vtxo").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// By calling bark vtxos we ensure the wallet is synced
	// This ensures bark knows the vtxo exists
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have refreshed one vtxo");
	let vtxo = &vtxos[0];

	// We stop the server
	srv.stop().await.unwrap();

	// Make bark exit and check the balance
	bark.start_exit_vtxos([vtxo.id]).await;
	complete_exit(&ctx, &bark).await;

	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1, "We have one exit");
	let exit = &exits[0];

	assert!(matches!(exit.state, ExitState::Spendable(_)), "Exit should be spendable");

	bark.claim_exits([exit.vtxo_id], bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(997_201));
}

#[tokio::test]
async fn exit_after_board() {
	let ctx = TestContext::new("exit/exit_after_board").await;
	let srv = ctx.new_captaind("server", None).await;

	// Fund the bark instance
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	// board funds
	bark.board(sat(900_000)).await;

	// Exit unilaterally
	srv.stop().await.unwrap();
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	let balance = bark.onchain_balance().await;
	assert!(balance > sat(900_000), "balance: {balance}");
}

#[tokio::test]
async fn exit_oor() {
	let ctx = TestContext::new("exit/exit_oor").await;
	let srv = ctx.new_captaind("server", None).await;

	// Bark1 will pay bark2 oor.
	// Bark2 will attempt an exit
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	ctx.generate_blocks(1).await;

	// Bark1 board funds and sends some part to bark2
	bark1.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let bark2_addr = bark2.address().await;
	bark1.send_oor(bark2_addr, sat(100_000)).await;

	// By calling bark2 vtxos we ensure the wallet is synced
	// This ensures bark2 knows the vtxo exists
	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have received one vtxo");

	// We stop the server
	srv.stop().await.unwrap();

	// Make bark2 exit and check the balance
	// It should be FUND_AMOUNT + VTXO_AMOUNT - fees
	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;

	bark2.claim_all_exits(bark2.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark2.onchain_balance().await, sat(1_096_376));
}

#[tokio::test]
async fn double_exit_call() {
	let ctx = TestContext::new("exit/double_exit_call").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;
	let bark3 = ctx.new_bark_with_funds("bark3", &srv, sat(1_000_000)).await;

	bark2.board(sat(500_000)).await;
	bark3.board(sat(500_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo. change will be ~170 000 sats
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet

	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 7);

	let last_moves = &movements[0..=2];
	assert!(
		vtxos.iter().all(|v| last_moves.iter().any(|m| {
				let exit_spk = exit_taproot(v.user_pubkey, v.server_pubkey, v.exit_delta).script_pubkey();
				let address = Address::from_script(&exit_spk, Params::REGTEST)
					.unwrap().to_string();
				m.spends.first().unwrap().id == v.id &&
					m.recipients[0].recipient == address.to_string()
			})
		),
		"each exited vtxo should be linked to a movement with exit_spk as destination"
	);
	assert_eq!(bark1.vtxos().await.len(), 0, "all vtxos should be marked as spent");

	// create a new vtxo to exit
	bark3.send_oor(bark1.address().await, sat(145_000)).await;
	let vtxos = bark1.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	let vtxo = vtxos.first().unwrap();

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;

	let movements = bark1.list_movements().await;
	assert_eq!(movements.len(), 9);

	// check we only exited last vtxo
	let last_move = movements.first().unwrap();
	assert_eq!(last_move.spends.len(), 1, "we should only exit last spendable vtxo");
	assert_eq!(last_move.spends.first().unwrap().id, vtxo.id);

	let exit_spk = exit_taproot(vtxo.user_pubkey, vtxo.server_pubkey, vtxo.exit_delta).script_pubkey();
	let address = Address::from_script(&exit_spk, Params::REGTEST).unwrap().to_string();
	assert_eq!(last_move.recipients[0].recipient, address, "movement destination should be exit_spk");

	assert_eq!(bark1.vtxos().await.len(), 0, "vtxo should be marked as spent");

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
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
	ctx.generate_blocks(6).await;
	lightningd_1.wait_for_block_sync().await;

	trace!("Creating channel between lightning nodes");
	lightningd_1.connect(&lightningd_2).await;
	let txid = lightningd_1.fund_channel(&lightningd_2, btc(8)).await;

	ctx.await_transaction(txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, btc(7)).await;

	let board_amount = btc(5);
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_amount = btc(2);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.send_lightning(invoice, None).await;
	assert_eq!(bark_1.offchain_balance().await, btc(3));

	// We try to perform an exit for ln payment change
	let vtxo = &bark_1.vtxos().await[0];

	srv.stop().await.unwrap();
	bark_1.start_exit_all().await;
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark_1.offchain_balance().await, Amount::ZERO);
	assert!(bark_1.onchain_balance().await >= vtxo.amount + Amount::ONE_SAT);
}

#[tokio::test]
async fn exit_revoked_lightning_payment() {
	let ctx = TestContext::new("exit/exit_revoked_lightning_payment").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// No channels are created so that payment will fail

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind("server", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &srv, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	srv.stop().await.unwrap();
	bark_1.start_exit_all().await;
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark_1.offchain_balance().await, Amount::ZERO);

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_should_exit_a_failed_htlc_out_that_server_refuse_to_revoke() {
	let ctx = TestContext::new("exit/bark_should_exit_a_failed_htlc_out_that_server_refuse_to_revoke").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_1), btc(10)).await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);

	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> server_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self,
			_req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			Err(tonic::Status::internal("Refused to finish bolt11 payment"))
		}

		async fn revoke_lightning_payment(
			&mut self,
			_req: protos::RevokeLightningPaymentRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::internal("Refused to revoke htlc out"))
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = captaind::proxy::ArkRpcProxyServer::start(proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	// vtxo expiry is 144, so exit should be triggered after 120 blocks
	ctx.generate_blocks(130).await;
	bark_1.maintain().await;

	// Should start an exit
	assert_eq!(bark_1.list_exits().await[0].state, ExitState::Start(ExitStartState { tip_height: 239 }));
	complete_exit(&ctx, &bark_1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_should_exit_a_pending_htlc_out_that_server_refuse_to_revoke() {
	let ctx = TestContext::new("exit/bark_should_exit_a_pending_htlc_out_that_server_refuse_to_revoke").await;

	// Start three lightning nodes and connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start a server and link it to our cln installation
	let srv = ctx.new_captaind_with_funds("server", Some(&lightningd_1), btc(10)).await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(captaind::ArkClient);

	#[tonic::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		fn upstream(&self) -> server_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self,
			_req: protos::SignedLightningPaymentDetails,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			Ok(protos::LightningPaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}

		async fn check_lightning_payment(
			&mut self,
			_req: protos::CheckLightningPaymentRequest,
		) -> Result<protos::LightningPaymentResult, tonic::Status> {
			Ok(protos::LightningPaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}

		async fn revoke_lightning_payment(
			&mut self,
			_req: protos::RevokeLightningPaymentRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::internal("Refused to revoke htlc out"))
		}
	}

	let proxy = Proxy(srv.get_public_rpc().await);
	let proxy = captaind::proxy::ArkRpcProxyServer::start(proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &proxy.address, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	// vtxo expiry is 144, so exit should be triggered after 120 blocks
	ctx.generate_blocks(130).await;
	bark_1.maintain().await;
	complete_exit(&ctx, &bark_1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_claim_specific_exit_in_low_fee_market() {
	let ctx = TestContext::new("exit/bark_claim_specific_exit_in_low_fee_market").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.try_new_bark_with_create_args::<String>(
		"bark",
		&srv.ark_url(),
		Some(FeeRate::from_sat_per_vb(1).unwrap()),
		[],
	).await.unwrap();
	ctx.fund_bark(&bark, sat(10_000_000)).await;

	// Create multiple VTXOs
	bark.board(sat(100_000)).await;
	bark.board(sat(50_000)).await;
	bark.board(sat(200_000)).await;
	bark.board(sat(1_000_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 4);
	let exits = vtxos.into_iter()
		.filter(|v| v.amount == sat(100_000) || v.amount == sat(50_000)).collect::<Vec<_>>();
	assert_eq!(exits.len(), 2);

	// Complete the exit process
	srv.stop().await.unwrap();
	bark.start_exit_vtxos(exits.iter().map(|v| v.id)).await;
	complete_exit(&ctx, &bark).await;

	let onchain_address = bark.get_onchain_address().await;
	bark.claim_exits(exits.iter().map(|v| v.id), onchain_address).await;
	assert_eq!(bark.onchain_balance().await, sat(8_798_621));
	assert_eq!(bark.utxos().await.len(), 2);
	assert_eq!(bark.vtxos().await.len(), 2);
}

#[tokio::test]
async fn bark_claim_all_exits_in_low_fee_market() {
	let ctx = TestContext::new("exit/bark_claim_all_exits_in_low_fee_market").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.try_new_bark_with_create_args::<String>(
		"bark",
		&srv.ark_url(),
		Some(FeeRate::from_sat_per_vb(1).unwrap()),
		[],
	).await.unwrap();
	ctx.fund_bark(&bark, sat(10_000_000)).await;

	// Create multiple VTXOs
	bark.board(sat(100_000)).await;
	bark.board(sat(50_000)).await;
	bark.board(sat(200_000)).await;
	bark.board(sat(1_000_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 4);

	// Complete the exit process
	srv.stop().await.unwrap();
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	let onchain_address = bark.get_onchain_address().await;
	bark.claim_all_exits(onchain_address).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(9_997_916));
	assert_eq!(bark.utxos().await.len(), 2);
	assert_eq!(bark.vtxos().await.len(), 0);
}

#[tokio::test]
async fn exit_spend_anchor_single_utxo_required() {
	let ctx = TestContext::new("exit/exit_spend_anchor_single_utxo_required").await;
	let srv = ctx.new_captaind("server", None).await;

	// We need to complete an exit whilst only using one UTXO to spend the anchor output
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(500_000)).await;

	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	// Verify that 1 UTXO + the P2A output are used
	let list = bark.list_exits_with_details().await;
	assert_eq!(list.len(), 1);
	let transactions = &list[0].transactions;
	assert_eq!(transactions.len(), 1);
	assert_eq!(transactions[0].child.as_ref().unwrap().info.tx.input.len(), 2);

	// Verify the final balance
	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(997_201));
}

#[tokio::test]
async fn exit_spend_anchor_multiple_utxos_required() {
	let ctx = TestContext::new("exit/exit_spend_anchor_multiple_utxos_required").await;
	let srv = ctx.new_captaind("server", None).await;

	// We need to complete an exit whilst using multiple UTXOs to spend the anchor output
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;
	bark.board_all().await;
	ctx.fund_bark(&bark, sat(777)).await;
	ctx.fund_bark(&bark, sat(562)).await;
	ctx.fund_bark(&bark, sat(988)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.maintain().await;

	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	// Verify that 3 UTXOs + the P2A output are used
	let list = bark.list_exits_with_details().await;
	assert_eq!(list.len(), 1);
	let transactions = &list[0].transactions;
	assert_eq!(transactions.len(), 1);
	assert_eq!(transactions[0].child.as_ref().unwrap().info.tx.input.len(), 4);

	// Verify the final balance
	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark.onchain_balance().await, sat(999_168));
}

#[tokio::test]
async fn exit_oor_ping_pong_then_rbf_tx() {
	let ctx = TestContext::new("exit/exit_oor_ping_pong_then_rbf_tx").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;

	let bark1 = ctx.try_new_bark_with_create_args::<String>(
		"bark1", &srv, FeeRate::from_sat_per_vb(1), [],
	).await.unwrap();
	let bark2 = ctx.try_new_bark_with_create_args::<String>(
		"bark2", &srv, FeeRate::from_sat_per_vb(100), [],
	).await.unwrap();

	ctx.fund_bark(&bark1, sat(1_000_000)).await;
	ctx.fund_bark(&bark2, sat(1_000_000)).await;
	bark1.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Bounce the same VTXO between the two barks
	bark1.send_oor(bark2.address().await, sat(550_000)).await;
	bark2.send_oor(bark1.address().await, sat(150_000)).await;
	bark1.send_oor(bark2.address().await, sat(500_000)).await;
	bark2.send_oor(bark1.address().await, sat(400_000)).await;

	// Force a sync
	bark1.vtxos().await;
	bark2.vtxos().await;

	// Exit the funds
	srv.stop().await.unwrap();
	bark1.start_exit_all().await;
	bark2.start_exit_all().await;

	// Progress once so we have transactions stuck in the mempool
	async fn await_propagation(ctx: &TestContext, primary: &Bark, secondary: &Bark) {
		let child_txs = primary.list_exits_with_details().await.into_iter().flat_map(|s| {
			s.transactions.into_iter().filter_map(|package| package.child)
		});
		for child_tx in child_txs {
			ctx.await_transaction_across_nodes(child_tx.info.txid, secondary.bitcoind()).await;
		}
	}

	bark1.progress_exit().await;
	await_propagation(&ctx, &bark1, &bark2).await;
	bark2.progress_exit().await;
	await_propagation(&ctx, &bark2, &bark1).await;
	assert_eq!(bark1.list_exits_with_details().await.len(), 1, "We should have one exit");
	assert_eq!(bark2.list_exits_with_details().await.len(), 2, "We have two exits");

	complete_exit(&ctx, &bark1).await;
	complete_exit(&ctx, &bark2).await;

	// Claim the funds and check we have the correct funds
	bark1.list_exits().await;
	bark2.list_exits().await;
	bark1.claim_all_exits(bark1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	bark2.claim_all_exits(bark2.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark1.onchain_balance().await, sat(498_799));
	assert_eq!(bark1.onchain_utxos().await.len(), 2, "We should have board change and a claim UTXO");
	assert_eq!(bark2.onchain_balance().await, sat(1_396_675));
	assert_eq!(bark2.onchain_utxos().await.len(), 2, "We should have the funding and a claim UTXO");
}
