

use bark_json::exit::states::ExitStartState;
use bark_json::exit::ExitState;
use bitcoin::Address;
use bitcoin::params::Params;
use bitcoin_ext::TaprootSpendInfoExt;
use bitcoincore_rpc::bitcoin::amount::Amount;
use bitcoincore_rpc::RpcApi;
use log::trace;

use ark::vtxo::exit_taproot;
use bark_json::cli::ExitProgressResponse;
use bark_json::exit::error::ExitError;

use ark_testing::{TestContext, Bark, btc, sat};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::aspd;

async fn complete_exit(ctx: &TestContext, bark: &Bark) {
	let mut flip = false;
	let mut did_generate_block = false;
	let mut previous : Option<ExitProgressResponse> = None;
	let mut attempts = 0;
	while attempts < 20 {
		attempts += 1;
		let response = bark.progress_exit().await;
		if !did_generate_block && previous.is_some() {
			// Progressing without generating blocks should be a no-op
			assert_eq!(response, *previous.as_ref().unwrap());
		}
		if response.done {
			return;
		}

		// Ideally, we would flip-flop between generating and not generating blocks unless we're
		// explicitly waiting for one
		let mut generate_block = flip;
		flip = !flip;

		// Panic early if an unexpected error occurs
		for exit in &response.exits {
			if let Some(e) = &exit.error {
				match e {
					ExitError::InsufficientConfirmedFunds { .. } => {
						generate_block = true;
					}
					_ => panic!("unexpected exit error: {:?}", e),
				}
			}
		}
		if response.exits.iter().any(|t| t.state.requires_confirmations()) {
			generate_block = true;
		}

		// Fast-forward if we're just waiting for confirmations
		if let Some(height) = response.spendable_height {
			let current = ctx.bitcoind().sync_client().get_block_count().unwrap() as u32;
			ctx.generate_blocks(height - current).await;
			did_generate_block = height - current > 0;
		} else if generate_block {
			ctx.generate_blocks(1).await;
			did_generate_block = true;
		}

		// Used to allow for an extra iteration if the status has changed
		if let Some(previous) = &previous {
			if response != *previous {
				attempts -= 1;
			}
		}
		previous = Some(response);
	}
	panic!("failed to finish unilateral exit of bark {}", bark.name());
}

#[tokio::test]
async fn simple_exit() {
	// Initialize the test
	let ctx = TestContext::new("exit/simple_exit").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark1".to_string(), &aspd, sat(1_000_000)).await;
	ctx.generate_blocks(1).await;

	bark.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	bark.refresh_all().await;

	aspd.stop().await.unwrap();
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Wallet has 1_000_000 sats of funds minus fees
	assert_eq!(bark.onchain_balance().await, sat(997_161));
}

#[tokio::test]
async fn exit_round() {
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

	bark1.start_exit_all().await;
	bark2.start_exit_all().await;
	bark3.start_exit_all().await;
	bark4.start_exit_all().await;
	bark5.start_exit_all().await;
	bark6.start_exit_all().await;
	bark7.start_exit_all().await;
	bark8.start_exit_all().await;

	complete_exit(&ctx, &bark1).await;
	complete_exit(&ctx, &bark2).await;
	complete_exit(&ctx, &bark3).await;
	complete_exit(&ctx, &bark4).await;
	complete_exit(&ctx, &bark5).await;
	complete_exit(&ctx, &bark6).await;
	complete_exit(&ctx, &bark7).await;
	complete_exit(&ctx, &bark8).await;

	bark1.claim_all_exits(bark1.get_onchain_address().await).await;
	bark2.claim_all_exits(bark2.get_onchain_address().await).await;
	bark3.claim_all_exits(bark3.get_onchain_address().await).await;
	bark4.claim_all_exits(bark4.get_onchain_address().await).await;
	bark5.claim_all_exits(bark5.get_onchain_address().await).await;
	bark6.claim_all_exits(bark6.get_onchain_address().await).await;
	bark7.claim_all_exits(bark7.get_onchain_address().await).await;
	bark8.claim_all_exits(bark8.get_onchain_address().await).await;
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
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;

	// By calling bark vtxos we ensure the wallet is synced
	// This ensures bark knows the vtxo exists
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have refreshed one vtxo");
	let vtxo = &vtxos[0];

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark exit and check the balance
	bark.start_exit_vtxo(vtxo.id).await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark.onchain_balance().await, sat(997_161));
}

#[tokio::test]
async fn exit_and_send_vtxo() {
	let ctx = TestContext::new("exit/exit_and_send_vtxo").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.refresh_all().await;

	// By calling bark vtxos we ensure the wallet is synced
	// This ensures bark knows the vtxo exists
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "We have refreshed one vtxo");
	let vtxo = &vtxos[0];

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark exit and check the balance
	bark.start_exit_vtxo(vtxo.id).await;
	complete_exit(&ctx, &bark).await;

	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1, "We have one exit");
	let exit = &exits[0];

	assert!(matches!(exit.state, ExitState::Spendable(_)), "Exit should be spendable");

	bark.claim_single_exit(exit.vtxo_id, bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(997_501));
}

#[tokio::test]
async fn exit_after_board() {
	let ctx = TestContext::new("exit/exit_after_board").await;
	let aspd = ctx.new_aspd("aspd", None).await;

	// Fund the bark instance
	let bark = ctx.new_bark_with_funds("bark", &aspd, sat(1_000_000)).await;

	// board funds
	bark.board(sat(900_000)).await;

	// Exit unilaterally
	aspd.stop().await.unwrap();
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
	let aspd = ctx.new_aspd("aspd", None).await;

	// Bark1 will pay bark2 oor.
	// Bark2 will attempt an exit
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

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

	// We stop the asp
	aspd.stop().await.unwrap();

	// Make bark2 exit and check the balance
	// It should be FUND_AMOUNT + VTXO_AMOUNT - fees
	bark2.start_exit_all().await;
	complete_exit(&ctx, &bark2).await;

	bark2.claim_all_exits(bark2.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	assert_eq!(bark2.onchain_balance().await, sat(1096121));
}

#[tokio::test]
async fn double_exit_call() {
	let ctx = TestContext::new("exit/double_exit_call").await;
	let aspd = ctx.new_aspd_with_funds("aspd", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &aspd, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &aspd, sat(1_000_000)).await;

	bark2.board(sat(800_000)).await;

	// refresh vtxo
	bark1.board(sat(200_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.refresh_all().await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo
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
				let exit_spk = exit_taproot(v.user_pubkey, v.asp_pubkey, v.exit_delta).script_pubkey();
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
	bark2.send_oor(bark1.address().await, sat(145_000)).await;
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

	let exit_spk = exit_taproot(vtxo.user_pubkey, vtxo.asp_pubkey, vtxo.exit_delta).script_pubkey();
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

	ctx.await_transaction(&txid).await;
	ctx.generate_blocks(6).await;

	lightningd_1.wait_for_gossip(1).await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, btc(7)).await;

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

	aspd_1.stop().await.unwrap();
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

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd("aspd-1", Some(&lightningd_1)).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.new_bark_with_funds("bark-1", &aspd_1, onchain_amount).await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightningd_2.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.offchain_balance().await, board_amount);
	bark_1.try_send_lightning(invoice, None).await.expect_err("The payment fails");

	aspd_1.stop().await.unwrap();
	bark_1.start_exit_all().await;
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark_1.offchain_balance().await, Amount::ZERO);

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_should_exit_a_failed_htlc_out_that_asp_refuse_to_revoke() {
	let ctx = TestContext::new("exit/bark_should_exit_a_failed_htlc_out_that_asp_refuse_to_revoke").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd_with_funds("aspd-1", Some(&lightningd_1), btc(10)).await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self,
			_req: aspd_rpc::protos::SignedLightningPaymentDetails,
		) -> Result<aspd_rpc::protos::LightningPaymentResult, tonic::Status> {
			Err(tonic::Status::internal("Refused to finish bolt11 payment"))
		}

		async fn revoke_lightning_payment(
			&mut self,
			_req: aspd_rpc::protos::RevokeLightningPaymentRequest,
		) -> Result<aspd_rpc::protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::internal("Refused to revoke htlc out"))
		}
	}

	let proxy = Proxy(aspd_1.get_public_client().await);
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

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

	// Triggers maintenance under the hood
	bark_1.offchain_balance().await;

	// Should start an exit
	assert_eq!(bark_1.list_exits().await[0].state, ExitState::Start(ExitStartState { tip_height: 248 }));
	complete_exit(&ctx, &bark_1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_should_exit_a_pending_htlc_out_that_asp_refuse_to_revoke() {
	let ctx = TestContext::new("exit/bark_should_exit_a_pending_htlc_out_that_asp_refuse_to_revoke").await;

	// Start a three lightning nodes
	// And connect them in a line.
	trace!("Start lightningd-1, lightningd-2, ...");
	let lightningd_1 = ctx.new_lightningd("lightningd-1").await;
	let lightningd_2 = ctx.new_lightningd("lightningd-2").await;

	// Start an aspd and link it to our cln installation
	let aspd_1 = ctx.new_aspd_with_funds("aspd-1", Some(&lightningd_1), btc(10)).await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy(aspd::ArkClient);

	#[tonic::async_trait]
	impl aspd::proxy::AspdRpcProxy for Proxy {
		fn upstream(&self) -> aspd_rpc::ArkServiceClient<tonic::transport::Channel> { self.0.clone() }

		async fn finish_lightning_payment(
			&mut self,
			_req: aspd_rpc::protos::SignedLightningPaymentDetails,
		) -> Result<aspd_rpc::protos::LightningPaymentResult, tonic::Status> {
			Ok(aspd_rpc::protos::LightningPaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: aspd_rpc::protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}

		async fn check_lightning_payment(
			&mut self,
			_req: aspd_rpc::protos::CheckLightningPaymentRequest,
		) -> Result<aspd_rpc::protos::LightningPaymentResult, tonic::Status> {
			Ok(aspd_rpc::protos::LightningPaymentResult {
				progress_message: "Payment is pending".to_string(),
				status: aspd_rpc::protos::PaymentStatus::Pending as i32,
				payment_hash: vec![],
				payment_preimage: None,
			})
		}

		async fn revoke_lightning_payment(
			&mut self,
			_req: aspd_rpc::protos::RevokeLightningPaymentRequest,
		) -> Result<aspd_rpc::protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::internal("Refused to revoke htlc out"))
		}
	}

	let proxy = Proxy(aspd_1.get_public_client().await);
	let proxy = aspd::proxy::AspdRpcProxyServer::start(proxy).await;

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

	// Triggers maintenance under the hood
	bark_1.offchain_balance().await;
	complete_exit(&ctx, &bark_1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet
}
