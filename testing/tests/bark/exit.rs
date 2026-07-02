use std::iter;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bark::actions::lightning::receive::LightningReceiveState;
use bitcoin::{Address, Amount, FeeRate, OutPoint};
use bitcoin::params::Params;
use futures::FutureExt;
use rand::random;


use ark::VtxoPolicy;
use ark::lightning::{Invoice, PaymentHash};
use ark::vtxo::{VtxoId, VtxoPolicyKind};
use bark_json::movements::{MovementDestination, MovementStatus, PaymentMethod};
use bark_json::exit::ExitState;
use bark_json::primitives::VtxoStateInfo;
use bitcoin_ext::TaprootSpendInfoExt;
use bitcoin_ext::rpc::BitcoinRpcExt;
use server_rpc::protos::{self, lightning_payment_status};

use ark_testing::{
	Bark, TestContext, btc, require_bark_version, require_bitcoind_chain_source, sat, signed_sat,
};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::daemon::captaind::{self, ArkClient};
use ark_testing::exit::{complete_exit, progress_exit_until_awaiting_delta};


#[tokio::test]
async fn simple_exit() {
	require_bark_version!(> "0.2.0");

	// Initialize the test
	let ctx = TestContext::new("exit/simple_exit").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	ctx.generate_blocks(1).await;

	bark.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	ctx.refresh_all(&srv, &[&bark]).await;
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
	require_bark_version!(> "0.2.0");

	// Initialize the test
	let ctx = TestContext::new("exit/exit_round").await;
	let srv = ctx.captaind("server").create().await;

	// Fund the server
	ctx.fund_captaind(&srv, btc(10)).await;

	// Create a few clients
	let create_bark = |name: &str| ctx.bark(name, &srv).cfg(|cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_kwu(250 + random::<u64>() % 24_750)); // 1 to 100 sats/vB
	}).try_create();
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

	// Trigger round while all barks try to refresh concurrently
	let barks = [&bark1, &bark2, &bark3, &bark4, &bark5, &bark6, &bark7, &bark8];
	let refresh_futs = barks.iter().map(|b| b.try_refresh_all_no_retry());
	let (_, results) = tokio::join!(
		srv.trigger_round(),
		futures::future::join_all(refresh_futs),
	);
	for r in results { r.expect("refresh failed"); }
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let bark1_round_vtxo = &bark1.vtxos().await[0];
	let bark2_round_vtxo = &bark2.vtxos().await[0];
	let bark3_round_vtxo = &bark3.vtxos().await[0];
	let bark4_round_vtxo = &bark4.vtxos().await[0];
	let bark5_round_vtxo = &bark5.vtxos().await[0];
	let bark6_round_vtxo = &bark6.vtxos().await[0];
	let bark7_round_vtxo = &bark7.vtxos().await[0];
	let bark8_round_vtxo = &bark8.vtxos().await[0];

	// Verify all clients participated in the same batched round
	assert!(
		[bark1_round_vtxo, bark2_round_vtxo, bark3_round_vtxo, bark4_round_vtxo,
		 bark5_round_vtxo, bark6_round_vtxo, bark7_round_vtxo, bark8_round_vtxo]
			.windows(2).all(|w| w[0].chain_anchor.txid == w[1].chain_anchor.txid),
		"all clients should participate in the same round"
	);

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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, &[&bark]).await;
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
	assert_eq!(bark.onchain_balance().await, sat(995_408));
}

#[tokio::test]
async fn exit_and_send_vtxo() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_and_send_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	ctx.generate_blocks(1).await;

	bark.board(sat(900_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	ctx.refresh_all(&srv, &[&bark]).await;
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

	assert!(matches!(exit.state, ExitState::Claimable(_)), "Exit should be spendable");

	bark.claim_exits([exit.vtxo_id], bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark.onchain_balance().await, sat(995_408));
}

#[tokio::test]
async fn exit_after_board() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_after_board").await;
	let srv = ctx.captaind("server").create().await;

	// Fund the bark instance
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_oor").await;
	let srv = ctx.captaind("server").create().await;

	// Bark1 will pay bark2 oor.
	// Bark2 will attempt an exit
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;

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
	assert_eq!(bark2.onchain_balance().await, sat(1_094_994));
}

#[tokio::test]
async fn double_exit_call() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/double_exit_call").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark1 = ctx.bark("bark1", &srv).funded(sat(1_000_000)).create().await;
	let bark2 = ctx.bark("bark2", &srv).funded(sat(1_000_000)).create().await;
	let bark3 = ctx.bark("bark3", &srv).funded(sat(1_000_000)).create().await;

	bark1.board(sat(200_000)).await;
	bark2.board(sat(500_000)).await;
	bark3.board(sat(500_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// refresh vtxo
	ctx.refresh_all(&srv, &[&bark1]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// board vtxo
	bark1.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// oor vtxo. change will be ~170 000 sats
	bark2.send_oor(&bark1.address().await, sat(330_000)).await;

	let vtxos = bark1.vtxos().await;

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;

	// TODO: Drain exit outputs then check balance in onchain wallet

	let movements = bark1.history().await;
	assert_eq!(movements.len(), 7);

	let last_moves = &movements[4..];
	assert!(
		vtxos.iter().all(|v| last_moves.iter().any(|m| {
				let exit_spk = VtxoPolicy::new_pubkey(v.user_pubkey)
					.taproot(v.server_pubkey, v.exit_delta, v.expiry_height).script_pubkey();
				let address = Address::from_script(&exit_spk, Params::REGTEST)
					.unwrap().to_string();
				*m.input_vtxos.first().unwrap() == v.id &&
					m.sent_to[0].destination == PaymentMethod::Bitcoin(address)
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

	let movements = bark1.history().await;
	assert_eq!(movements.len(), 9);

	// check we only exited last vtxo
	let last_move = movements.last().unwrap();
	assert_eq!(last_move.input_vtxos.len(), 1, "we should only exit last spendable vtxo");
	assert_eq!(*last_move.input_vtxos.first().unwrap(), vtxo.id);
	assert_eq!(bark1.vtxos().await.len(), 0, "vtxo should be marked as spent");

	let exit_spk = VtxoPolicy::new_pubkey(vtxo.user_pubkey)
		.taproot(vtxo.server_pubkey, vtxo.exit_delta, vtxo.expiry_height).script_pubkey();
	let address = Address::from_script(&exit_spk, Params::REGTEST).unwrap().to_string();
	assert_eq!(last_move.sent_to[0].destination, PaymentMethod::Bitcoin(address), "movement destination should be exit_spk");

	assert_eq!(bark1.vtxos().await.len(), 0, "vtxo should be marked as spent");

	bark1.start_exit_all().await;
	complete_exit(&ctx, &bark1).await;
	assert_eq!(bark1.history().await.len(), 9, "should not create new movement when no new vtxo to exit");
}

#[tokio::test]
async fn exit_bolt11_change() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_bolt11_change").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.internal).create().await;

	// Start a bark and create a VTXO
	let bark_1 = ctx.bark("bark-1", &srv).funded(btc(7)).create().await;

	let board_amount = btc(5);
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let invoice_amount = btc(2);
	let invoice = lightning.external.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Ensure receive node is synced
	lightning.sync().await;

	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.pay_lightning_wait(invoice, None).await;
	assert_eq!(bark_1.spendable_balance().await, btc(3));

	// We try to perform an exit for ln payment change
	let vtxo = &bark_1.vtxos().await[0];

	srv.stop().await.unwrap();
	bark_1.start_exit_all().await;
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark_1.spendable_balance().await, Amount::ZERO);
	assert!(bark_1.onchain_balance().await >= vtxo.amount + Amount::ONE_SAT);
}

#[tokio::test]
async fn exit_revoked_lightning_payment() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_revoked_lightning_payment").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	// No channels are created so that payment will fail

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.internal).create().await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.bark("bark-1", &srv).funded(onchain_amount).create().await;

	// Board funds into the Ark
	bark_1.board_and_confirm_and_register(&ctx, board_amount).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = lightning.external.invoice(Some(invoice_amount), "test_payment", "A test payment").await;

	// Try send coins through lightning
	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.pay_lightning_wait(invoice, None).await;

	srv.stop().await.unwrap();
	bark_1.start_exit_all().await;
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark_1.spendable_balance().await, Amount::ZERO);

	// TODO: Drain exit outputs then check balance in onchain wallet
}

#[tokio::test]
async fn bark_should_exit_a_pending_board() {
	require_bark_version!(> "0.2.5");

	let ctx = TestContext::new("exit/bark_should_exit_a_pending_board").await;

	#[derive(Clone)]
	struct InvalidSigProxy;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for InvalidSigProxy {
		async fn register_board_vtxo(
			&self,
			_upstream: &mut ArkClient,
			_req: protos::BoardVtxoRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Err(tonic::Status::invalid_argument("Invalid signature"))
		}
	}

	let srv = ctx.captaind("server").create().await;
	let proxy = srv.start_proxy_no_mailbox(InvalidSigProxy).await;
	let bark = ctx.bark("bark1", &proxy.address).funded(sat(1_000_000)).create().await;
	let board_amount = sat(500_000);
	let res = bark.try_board(board_amount).await;
	assert!(res.is_ok(), "board should succeed");

	// Nothing should happen until the board is almost expired
	assert_eq!(bark.list_exits().await.len(), 0, "no exit should be triggered");
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;
	assert_eq!(bark.list_exits().await.len(), 0, "no exit should be triggered");
	assert_eq!(bark.pending_board_balance().await, board_amount, "board should still be pending because the server is refusing to register");

	let board_mvt = bark.history().await.last().cloned().unwrap();
	assert_eq!(board_mvt.status, MovementStatus::Pending);
	assert_eq!(board_mvt.subsystem.name, "bark.board");
	assert_eq!(board_mvt.subsystem.kind, "board");
	assert_eq!(board_mvt.intended_balance, board_amount.to_signed().unwrap());
	assert_eq!(board_mvt.effective_balance, board_amount.to_signed().unwrap());
	assert_eq!(board_mvt.offchain_fee, sat(0));
	assert_eq!(board_mvt.sent_to.len(), 0);
	assert_eq!(board_mvt.received_on.len(), 0);
	assert_eq!(board_mvt.input_vtxos.len(), 0);
	assert_eq!(board_mvt.output_vtxos.len(), 1);
	assert_eq!(board_mvt.exited_vtxos.len(), 0);
	assert_eq!(board_mvt.time.completed_at.is_some(), false);

	// Bring the board near to its expiry
	let board_vtxo = bark.vtxos().await.first().cloned().unwrap();
	let board_expiry = board_vtxo.expiry_height;
	let tip = ctx.bitcoind().sync_client().tip().unwrap().height;
	ctx.generate_blocks(board_expiry - tip - 2).await;
	bark.sync().await;

	// An exit has kicked off but the pending_board entry stays alive so registration
	// will keep retrying if the server becomes available. The funds therefore stay in
	// `pending_board`; they only move to `pending_exit` once the exit commits past
	// Start/Processing (i.e. reaches `AwaitingDelta`).
	assert_eq!(bark.list_exits().await.len(), 1, "exit should be triggered");
	assert_eq!(bark.pending_board_balance().await, board_amount,
		"board entry should still be retried until the exit commits on-chain");
	assert_eq!(bark.offchain_balance().await.pending_exit, Some(Amount::ZERO),
		"pending_exit is empty while the exit is still in its abortable window");

	let movements = bark.history().await;
	let board_mvt = movements.first().unwrap();
	assert_eq!(board_mvt.status, MovementStatus::Pending);
	assert_eq!(board_mvt.subsystem.name, "bark.board");
	assert_eq!(board_mvt.subsystem.kind, "board");
	assert_eq!(board_mvt.intended_balance, board_amount.to_signed().unwrap());
	assert_eq!(board_mvt.effective_balance, board_amount.to_signed().unwrap());
	assert_eq!(board_mvt.offchain_fee, sat(0));
	assert_eq!(board_mvt.sent_to.len(), 0);
	assert_eq!(board_mvt.received_on.len(), 0);
	assert_eq!(board_mvt.input_vtxos.len(), 0);
	assert_eq!(board_mvt.output_vtxos.len(), 1);
	assert_eq!(*board_mvt.output_vtxos.first().unwrap(), board_vtxo.id);
	assert_eq!(board_mvt.exited_vtxos.len(), 1);
	assert_eq!(*board_mvt.exited_vtxos.first().unwrap(), board_vtxo.id);
	assert_eq!(board_mvt.time.completed_at.is_some(), false);
	let metadata = board_mvt.metadata.as_ref().unwrap();
	let chain_anchor = metadata.get("chain_anchor").map(|ca| serde_json::from_value::<OutPoint>(ca.clone()).unwrap());
	assert!(chain_anchor.is_some(), "chain anchor should be present");
	let onchain_fee = metadata.get("onchain_fee_sat").map(|of| Amount::from_sat(serde_json::from_value::<u64>(of.clone()).unwrap()));
	assert_eq!(onchain_fee, Some(sat(772)));

	// Now verify that the exit can complete
	complete_exit(&ctx, &bark).await;
	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	// One more progress pass so the exit state advances from Claimable → Claimed
	// now that the drain tx has confirmed — that's what flips the movement to Successful.
	bark.progress_exit().await;
	assert_eq!(bark.onchain_balance().await, sat(997_201));

	// Re-fetch the exit movement once the exit has completed — it should now be Successful.
	let movements = bark.history().await;
	let board_mvt = movements.first().unwrap();
	assert_eq!(board_mvt.status, MovementStatus::Failed);
	assert_eq!(board_mvt.time.completed_at.is_some(), true);

	let exit_mvt = movements.iter().find(|m| m.subsystem.name == "bark.exit")
		.expect("exit movement should exist");
	assert_eq!(exit_mvt.status, MovementStatus::Successful);
	assert_eq!(exit_mvt.subsystem.name, "bark.exit");
	assert_eq!(exit_mvt.subsystem.kind, "start");
	assert_eq!(exit_mvt.intended_balance, -board_amount.to_signed().unwrap());
	assert_eq!(exit_mvt.effective_balance, -board_amount.to_signed().unwrap());
	assert_eq!(exit_mvt.offchain_fee, sat(0));
	assert_eq!(exit_mvt.sent_to.len(), 1);
	assert_eq!(exit_mvt.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Bitcoin({
			let exit_spk = VtxoPolicy::new_pubkey(board_vtxo.user_pubkey)
				.taproot(board_vtxo.server_pubkey, board_vtxo.exit_delta, board_vtxo.expiry_height)
				.script_pubkey();
			Address::from_script(&exit_spk, Params::REGTEST).unwrap().to_string()
		}),
		amount: board_amount,
	});
	assert_eq!(exit_mvt.received_on.len(), 0);
	assert_eq!(exit_mvt.input_vtxos.len(), 1);
	assert_eq!(*exit_mvt.input_vtxos.first().unwrap(), board_vtxo.id);
	assert_eq!(exit_mvt.output_vtxos.len(), 0);
	assert_eq!(exit_mvt.exited_vtxos.len(), 0);
	assert!(exit_mvt.time.completed_at.is_some());
}

#[tokio::test]
async fn bark_should_exit_a_failed_htlc_out_that_server_refuse_to_revoke() {
	require_bark_version!(> "0.2.5");

	let ctx = TestContext::new("exit/bark_should_exit_a_failed_htlc_out_that_server_refuse_to_revoke").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	// No channels are created so that payment will fail

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, _upstream: &mut ArkClient, _req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Err(tonic::Status::invalid_argument("Refused to finish bolt11 payment"))
		}

		async fn request_lightning_pay_htlc_revocation(
			&self, _upstream: &mut ArkClient, _req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::invalid_argument("Refused to revoke htlc out"))
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.bark("bark-1", &proxy.address).funded(onchain_amount).create().await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = Invoice::from_str(
		&lightning.external.invoice(Some(invoice_amount), "test_payment", "A test payment").await,
	).unwrap();

	// Tip at lightning send attempt time
	let tip = ctx.bitcoind().sync_client().tip().unwrap();

	// Try to send coins through lightning
	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.try_pay_lightning(invoice.to_string(), None, false).await
		.expect_err("The payment fails");

	// The send is now parked in `RevocationFailed`. Advance past the
	// refresh window so the on_rejection exit branch becomes reachable.
	let bark1_client = bark_1.client().await;
	let htlc_expiry_height = bark1_client.all_vtxos().await.unwrap().into_iter().find_map(
		|v| v.policy().as_server_htlc_send().map(|h| h.htlc_expiry)
	).unwrap();
	ctx.generate_blocks(htlc_expiry_height - tip.height).await;

	// Without `allow_lightning_send_to_exit`, even at expiry the action
	// must keep parking - no exit may be started, and the send must be
	// reported as stuck.
	let _ = bark1_client.check_lightning_payment(invoice.payment_hash(), false).await;
	assert!(
		bark_1.list_exits().await.is_empty(),
		"exit must not start without `allow_lightning_send_to_exit`",
	);
	assert_eq!(
		bark1_client.stuck_failed_lightning_sends().await.unwrap().len(), 1,
		"send should be reported as stuck",
	);

	// Opting in and re-driving must register the exit.
	bark1_client.allow_lightning_send_to_exit(invoice.payment_hash()).await.unwrap();
	let _ = bark1_client.check_lightning_payment(invoice.payment_hash(), true).await;

	// Should start an exit
	let exit_state = &bark_1.list_exits().await[0].state;
	assert!(
		matches!(exit_state, ExitState::Start(_) | ExitState::Processing(_)),
		"Expected exit to be starting, got {:?}", exit_state,
	);
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	// Drive the exit past Claimable → Claimed now that the drain has confirmed.
	bark_1.progress_exit().await;

	assert_eq!(bark_1.onchain_balance().await, sat(199_994_174));

	// Check that we have a lightning send -> exit movement chain
	let movements = bark_1.history().await;
	let [.., send_movement, exit_movement] = movements.as_slice() else {
		panic!("Should have at least two movements");
	};

	// Verify send movement
	assert_eq!(send_movement.status, MovementStatus::Failed);
	assert_eq!(send_movement.subsystem.name, "bark.lightning_send");
	assert_eq!(send_movement.subsystem.kind, "send");
	assert_eq!(send_movement.intended_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(send_movement.effective_balance, signed_sat(0));
	assert_eq!(send_movement.offchain_fee, sat(0));
	assert_eq!(send_movement.sent_to.len(), 1);
	assert_eq!(send_movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: invoice_amount,
	});
	assert_eq!(send_movement.received_on.len(), 0);
	assert_eq!(send_movement.input_vtxos.len(), 1);
	assert_eq!(send_movement.output_vtxos.len(), 1); // HTLC VTXOs aren't included here
	assert_eq!(send_movement.exited_vtxos.len(), 1); // HTLC VTXO is included here
	assert_eq!(send_movement.time.completed_at.is_some(), true);

	assert_eq!(send_movement.metadata.is_some(), true);
	let metadata = send_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	let htlc_vtxos = metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap();
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(htlc_vtxos.len(), 1);
	assert_eq!(send_movement.exited_vtxos, htlc_vtxos);

	// Verify exit movement
	assert_eq!(exit_movement.status, MovementStatus::Successful);
	assert_eq!(exit_movement.subsystem.name, "bark.exit");
	assert_eq!(exit_movement.subsystem.kind, "start");
	assert_eq!(exit_movement.intended_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(exit_movement.effective_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(exit_movement.offchain_fee, sat(0));
	assert_eq!(exit_movement.sent_to.len(), 1);
	let sent_to = exit_movement.sent_to.first().unwrap();
	assert!(matches!(sent_to.destination, PaymentMethod::Bitcoin(_))); // TODO: Can we rebuild the output address with VtxoInfo?
	assert_eq!(sent_to.amount, invoice_amount);
	assert_eq!(exit_movement.received_on.len(), 0);
	assert_eq!(exit_movement.input_vtxos.len(), 1);
	assert_eq!(exit_movement.input_vtxos, htlc_vtxos);
	assert_eq!(exit_movement.output_vtxos.len(), 0);
	assert_eq!(exit_movement.exited_vtxos.len(), 0);
	assert_eq!(exit_movement.time.completed_at.is_some(), true);
	assert_eq!(exit_movement.metadata.is_none(), true);
}

#[tokio::test]
async fn bark_should_exit_a_pending_htlc_out_that_server_refuse_to_revoke() {
	require_bark_version!(> "0.2.5");

	let ctx = TestContext::new("exit/bark_should_exit_a_pending_htlc_out_that_server_refuse_to_revoke").await;

	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	// No channels are created so that payment will fail

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("server").lightningd(&lightning.internal).funded(btc(10)).create().await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn initiate_lightning_payment(
			&self, _upstream: &mut ArkClient, _req: protos::InitiateLightningPaymentRequest,
		) -> Result<protos::Empty, tonic::Status> {
			Ok(protos::Empty {})
		}

		async fn check_lightning_payment(
			&self, _upstream: &mut ArkClient,
			_req: protos::CheckLightningPaymentRequest,
		) -> Result<protos::LightningPaymentStatus, tonic::Status> {
			Ok(protos::LightningPaymentStatus {
				payment_status: Some(lightning_payment_status::PaymentStatus::Pending(protos::Empty {})),
			})
		}

		async fn request_lightning_pay_htlc_revocation(
			&self, _upstream: &mut ArkClient,
			_req: protos::ArkoorPackageCosignRequest,
		) -> Result<protos::ArkoorPackageCosignResponse, tonic::Status> {
			Err(tonic::Status::internal("Refused to revoke htlc out"))
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO
	let onchain_amount = btc(3);
	let board_amount = btc(2);
	let bark_1 = ctx.bark("bark-1", &proxy.address).funded(onchain_amount).create().await;

	// Board funds into the Ark
	bark_1.board(board_amount).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Create a payable invoice
	let invoice_amount = btc(1);
	let invoice = Invoice::from_str(
		&lightning.external.invoice(Some(invoice_amount), "test_payment", "A test payment").await,
	).unwrap();

	// Try send coins through lightning
	assert_eq!(bark_1.spendable_balance().await, board_amount);
	bark_1.pay_lightning(invoice.to_string(), None).await;

	// We need to ensure the HTLC expires so an exit will be triggered.
	let tip = ctx.bitcoind().sync_client().tip().unwrap();
	let desired_height = {
		let bark = bark_1.client().await;
		let htlc = bark.vtxos().await.unwrap().into_iter().find(
			|v| v.policy_type() == VtxoPolicyKind::ServerHtlcSend
		).unwrap();
		htlc.expiry_height() - bark.config().vtxo_refresh_expiry_threshold + 1
	};
	ctx.generate_blocks(desired_height - tip.height).await;

	// Without `allow_lightning_send_to_exit`, the sync moves the action
	// through `RevocableHtlcs` → `RevocationFailed` and parks, but does
	// not start any exit. The send must be reported as stuck.
	bark_1.sync().await;
	assert!(
		bark_1.list_exits().await.is_empty(),
		"exit must not start without `allow_lightning_send_to_exit`",
	);
	assert_eq!(
		bark_1.client().await.stuck_failed_lightning_sends().await.unwrap().len(), 1,
		"send should be reported as stuck",
	);

	// Opt in and sync again: the on_retry branch picks up the flag and
	// the action exits its HTLCs.
	bark_1.client().await.allow_lightning_send_to_exit(invoice.payment_hash()).await.unwrap();
	bark_1.sync().await;

	// Should start an exit
	let exit_state = &bark_1.list_exits().await[0].state;
	assert!(
		matches!(exit_state, ExitState::Start(_) | ExitState::Processing(_)),
		"Expected exit to be starting, got {:?}", exit_state,
	);
	complete_exit(&ctx, &bark_1).await;

	bark_1.claim_all_exits(bark_1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	// Drive the exit past Claimable → Claimed now that the drain has confirmed.
	bark_1.progress_exit().await;
	assert_eq!(bark_1.onchain_balance().await, sat(199_994_174));

	assert_eq!(bark_1.offchain_balance().await.pending_lightning_send, btc(0));
	let vtxos = bark_1.vtxos().await;
	assert!(!vtxos.iter().any(|v| matches!(v.state, VtxoStateInfo::Locked { .. })), "should not be any locked vtxo left");

	// Check that we have a lightning send -> exit movement chain
	let movements = bark_1.history().await;
	let [.., send_movement, exit_movement] = movements.as_slice() else {
		panic!("Should have at least two movements");
	};

	// Verify send movement
	assert_eq!(send_movement.status, MovementStatus::Failed);
	assert_eq!(send_movement.subsystem.name, "bark.lightning_send");
	assert_eq!(send_movement.subsystem.kind, "send");
	assert_eq!(send_movement.intended_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(send_movement.effective_balance, signed_sat(0));
	assert_eq!(send_movement.offchain_fee, sat(0));
	assert_eq!(send_movement.sent_to.len(), 1);
	assert_eq!(send_movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: invoice_amount,
	});
	assert_eq!(send_movement.received_on.len(), 0);
	assert_eq!(send_movement.input_vtxos.len(), 1);
	assert_eq!(send_movement.output_vtxos.len(), 1); // HTLC VTXOs aren't included here
	assert_eq!(send_movement.exited_vtxos.len(), 1); // HTLC VTXO is included here
	assert_eq!(send_movement.time.completed_at.is_some(), true);

	assert_eq!(send_movement.metadata.is_some(), true);
	let metadata = send_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	let htlc_vtxos = metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap();
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(htlc_vtxos.len(), 1);
	assert_eq!(send_movement.exited_vtxos, htlc_vtxos);

	// Verify exit movement
	assert_eq!(exit_movement.status, MovementStatus::Successful);
	assert_eq!(exit_movement.subsystem.name, "bark.exit");
	assert_eq!(exit_movement.subsystem.kind, "start");
	assert_eq!(exit_movement.intended_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(exit_movement.effective_balance, -invoice_amount.to_signed().unwrap());
	assert_eq!(exit_movement.offchain_fee, sat(0));
	assert_eq!(exit_movement.sent_to.len(), 1);
	let sent_to = exit_movement.sent_to.first().unwrap();
	assert!(matches!(sent_to.destination, PaymentMethod::Bitcoin(_))); // TODO: Can we rebuild the output address with VtxoInfo?
	assert_eq!(exit_movement.received_on.len(), 0);
	assert_eq!(exit_movement.input_vtxos.len(), 1);
	assert_eq!(exit_movement.input_vtxos, htlc_vtxos);
	assert_eq!(exit_movement.output_vtxos.len(), 0);
	assert_eq!(exit_movement.exited_vtxos.len(), 0);
	assert_eq!(exit_movement.time.completed_at.is_some(), true);
	assert_eq!(exit_movement.metadata.is_none(), true);
}

#[tokio::test]
async fn bark_claim_specific_exit_in_low_fee_market() {
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/bark_claim_specific_exit_in_low_fee_market").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).cfg(|cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb(1).unwrap());
	}).try_create().await.unwrap();
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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/bark_claim_all_exits_in_low_fee_market").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).cfg(|cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb(1).unwrap());
	}).try_create().await.unwrap();
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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_spend_anchor_single_utxo_required").await;
	let srv = ctx.captaind("server").create().await;

	// We need to complete an exit whilst only using one UTXO to spend the anchor output
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board_and_confirm_and_register(&ctx, sat(500_000)).await;

	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	// Verify that 1 UTXO + the P2A output are used
	let list = bark.list_exits_with_txs().await;
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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_spend_anchor_multiple_utxos_required").await;
	let srv = ctx.captaind("server").create().await;

	// We need to complete an exit whilst using multiple UTXOs to spend the anchor output
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;
	bark.board_all().await;
	ctx.fund_bark(&bark, sat(777)).await;
	ctx.fund_bark(&bark, sat(562)).await;
	ctx.fund_bark(&bark, sat(988)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	// Verify that 3 UTXOs + the P2A output are used
	let list = bark.list_exits_with_txs().await;
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
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("exit/exit_oor_ping_pong_then_rbf_tx").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let mut bark1 = ctx.bark("bark1", &srv).cfg(|cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb_u32(1));
	}).try_create().await.unwrap();
	let mut bark2 = ctx.bark("bark2", &srv).cfg(|cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_vb_u32(100));
	}).try_create().await.unwrap();
	bark1.set_timeout(Duration::from_secs(2 * 60));
	bark2.set_timeout(Duration::from_secs(2 * 60));

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
	bark1.sync().await;
	bark2.sync().await;

	// Exit the funds
	srv.stop().await.unwrap();
	bark1.start_exit_all().await;
	bark2.start_exit_all().await;

	// Progress once so we have transactions stuck in the mempool
	async fn await_propagation(ctx: &TestContext, primary: &Bark, secondary: &Bark) {
		// We have to use the no-sync variant until we track the fee-rate of packages built
		// from the onchain wallet and those broadcast by a third party. Else the syncing process
		// will download a lower fee-rate package from the mempool until esplora syncs the higher
		// fee-rate package.
		let child_txs = primary.list_exits_with_txs_no_sync().await.into_iter().flat_map(|s| {
			s.transactions.into_iter().filter_map(|package| package.child)
		});
		ctx.await_transactions_across_nodes(
			child_txs.into_iter().map(|child_tx| child_tx.info.txid),
			iter::once(secondary).filter_map(|b| b.bitcoind()),
		).await;
	}

	bark1.progress_exit().await;
	await_propagation(&ctx, &bark1, &bark2).await;
	bark2.progress_exit().await;

	await_propagation(&ctx, &bark2, &bark1).await;
	assert_eq!(bark1.list_exits().await.len(), 1, "We should have one exit");
	assert_eq!(bark2.list_exits().await.len(), 2, "We have two exits");

	complete_exit(&ctx, &bark1).await;
	complete_exit(&ctx, &bark2).await;

	// Claim the funds and check we have the correct funds
	bark1.list_exits().await;
	bark2.list_exits().await;
	bark1.claim_all_exits(bark1.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	bark2.claim_all_exits(bark2.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	assert_eq!(bark1.onchain_balance().await, sat(497_968));
	assert_eq!(bark1.onchain_utxos().await.len(), 2, "We should have board change and a claim UTXO");
	assert_eq!(bark2.onchain_balance().await, sat(1_286_175));
	assert_eq!(bark2.onchain_utxos().await.len(), 2, "We should have the funding and a claim UTXO");
}

#[tokio::test]
async fn bark_should_exit_a_htlc_recv_that_server_refuse_to_cosign() {
	require_bark_version!(> "0.3.0");

	let ctx = TestContext::new("exit/bark_should_exit_a_htlc_recv_that_server_refuse_to_cosign").await;
	let ctx = Arc::new(ctx);

	let lightning = ctx.new_lightning_setup("lightningd").await;

	// Start a server and link it to our cln installation
	let srv = ctx.captaind("srv").lightningd(&lightning.internal).funded(btc(10)).create().await;

	/// This proxy will refuse to revoke the htlc out.
	#[derive(Clone)]
	struct Proxy;
	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for Proxy {
		async fn claim_lightning_receive(
			&self,
			upstream: &mut ArkClient,
			req: server_rpc::protos::ClaimLightningReceiveRequest,
		) -> Result<server_rpc::protos::ArkoorPackageCosignResponse, tonic::Status> {
			upstream.claim_lightning_receive(req).await?;
			Err(tonic::Status::invalid_argument("Refused to finish bolt11 board"))
		}
	}

	let proxy = srv.start_proxy_no_mailbox(Proxy).await;

	// Start a bark and create a VTXO to be able to board. The claim retry
	// budget is not under test here, so drop it to fail fast.
	let bark = ctx.bark("bark", &proxy.address).funded(btc(2.1)).cfg(|cfg| {
		cfg.lightning_receive_claim_retries = 0;
	}).create().await;
	bark.board(btc(2)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	let lightning_board_amount = btc(1);
	let invoice_info = bark.bolt11_invoice(lightning_board_amount).await;

	let cloned_invoice_info = invoice_info.clone();
	let res1 = tokio::spawn(async move {
		lightning.external.pay_bolt11(cloned_invoice_info.invoice).await;
	});

	let _ = bark.try_lightning_receive(&invoice_info.invoice).await;

	res1.await.unwrap();

	// The server refused to cosign the claim, but we no longer exit
	// automatically: the receive must stay pending so the claim can be
	// retried later.
	bark.sync().await;
	assert!(bark.list_exits().await.is_empty(),
		"no exit should start without an explicit exit attempt");

	let invoice = Invoice::from_str(&invoice_info.invoice).unwrap();
	let client = bark.client().await;
	let receive = match client
		.lightning_receive_state(invoice.payment_hash()).await
		.expect("the lightning receive should be created")
	{
		LightningReceiveState::InProgress(receive) => receive,
		LightningReceiveState::Settled(_) => {
			panic!("the lightning receive should not be settled");
		},
	};

	assert!(matches!(receive.progress, bark::actions::lightning::receive::Progress::PreimageRevealed(_)),
		"the lightning receive should be in the preimage revealed state");

	// Explicitly fall back to exiting the HTLC VTXOs on-chain.
	client.attempt_lightning_receive_exit(invoice.payment_hash()).await.unwrap();

	assert!(!bark.list_exits().await.is_empty(), "Expected exit to be started");
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	// Drive the exit past Claimable → Claimed now that the drain has confirmed.
	bark.progress_exit().await;

	assert_eq!(bark.onchain_balance().await, sat(109_993_699));

	// Check that we have a lightning receive -> exit movement chain
	let movements = bark.history().await;
	let [.., ln_movement, exit_movement] = movements.as_slice() else {
		panic!("Should have at least two movements");
	};

	// Verify receive movement
	assert_eq!(ln_movement.status, MovementStatus::Failed);
	assert_eq!(ln_movement.subsystem.name, "bark.lightning_receive");
	assert_eq!(ln_movement.subsystem.kind, "receive");
	assert_eq!(ln_movement.intended_balance, lightning_board_amount.to_signed().unwrap());
	assert_eq!(ln_movement.effective_balance, lightning_board_amount.to_signed().unwrap());
	assert_eq!(ln_movement.offchain_fee, sat(0));
	assert_eq!(ln_movement.sent_to.len(), 0);
	assert_eq!(ln_movement.received_on.len(), 1);
	assert_eq!(ln_movement.received_on.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: lightning_board_amount,
	});
	assert_eq!(ln_movement.input_vtxos.len(), 0);
	assert_eq!(ln_movement.output_vtxos.len(), 0); // HTLC VTXOs aren't included here
	assert_eq!(ln_movement.exited_vtxos.len(), 1); // HTLC VTXOs are included here
	assert_eq!(ln_movement.time.completed_at.is_some(), true);

	assert_eq!(ln_movement.metadata.is_some(), true);
	let metadata = ln_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	let htlc_vtxos = metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap();
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(htlc_vtxos.len(), 1);
	assert_eq!(ln_movement.exited_vtxos, htlc_vtxos);

	// Verify exit movement
	assert_eq!(exit_movement.status, MovementStatus::Successful);
	assert_eq!(exit_movement.subsystem.name, "bark.exit");
	assert_eq!(exit_movement.subsystem.kind, "start");
	assert_eq!(exit_movement.intended_balance, -lightning_board_amount.to_signed().unwrap());
	assert_eq!(exit_movement.effective_balance, -lightning_board_amount.to_signed().unwrap());
	assert_eq!(exit_movement.offchain_fee, sat(0));
	assert_eq!(exit_movement.sent_to.len(), 1);
	let sent_to = exit_movement.sent_to.first().unwrap();
	assert!(matches!(sent_to.destination, PaymentMethod::Bitcoin(_)));
	assert_eq!(sent_to.amount, lightning_board_amount);
	assert_eq!(exit_movement.received_on.len(), 0);
	assert_eq!(exit_movement.input_vtxos.len(), 1);
	assert_eq!(exit_movement.input_vtxos, htlc_vtxos);
	assert_eq!(exit_movement.output_vtxos.len(), 0);
	assert_eq!(exit_movement.exited_vtxos.len(), 0);
	assert_eq!(exit_movement.time.completed_at.is_some(), true);
	assert_eq!(exit_movement.metadata.is_none(), true);
}

/// Once a VTXO is queued for exit but before the chain has broadcast, the wallet should
/// still let the user spend it via the normal Ark protocol — refresh, OOR send, etc. If
/// that happens, the exit progress code notices the VTXO is gone and transitions to the
/// terminal `VtxoAlreadySpent` state with the exit movement Canceled.
#[tokio::test]
async fn vtxo_remains_spendable_while_exit_pending() {
	require_bark_version!(> "0.2.5");

	let ctx = TestContext::new("exit/vtxo_remains_spendable_while_exit_pending").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	bark.board_and_confirm_and_register(&ctx, sat(500_000)).await;
	let board_vtxos = bark.vtxos().await;
	assert_eq!(board_vtxos.len(), 1);
	let original_id = board_vtxos[0].id;

	// Queue the VTXO for exit but don't progress it yet — it should remain Spendable
	// and visible to coin selection.
	bark.start_exit_all().await;
	let after_start = bark.vtxos().await;
	assert_eq!(after_start.len(), 1, "vtxo should remain in spendable set");
	assert!(matches!(after_start[0].state, VtxoStateInfo::Spendable),
		"vtxo state should still be Spendable, got {:?}", after_start[0].state);

	// Refresh through a round — this consumes the original VTXO and produces a new one.
	ctx.refresh_all(&srv, &[&bark]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let after_refresh = bark.vtxos().await;
	assert_eq!(after_refresh.len(), 1, "refresh should produce a new vtxo");
	assert_ne!(after_refresh[0].id, original_id,
		"the original vtxo should have been replaced by the round output");

	// Now progress the exit — it should detect the original VTXO has been spent and
	// abort to the VtxoAlreadySpent terminal state.
	bark.progress_exit().await;

	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1);
	assert_eq!(exits[0].vtxo_id, original_id);
	assert!(matches!(exits[0].state, ExitState::VtxoAlreadySpent(_)),
		"exit should be in VtxoAlreadySpent, got {:?}", exits[0].state);

	// And the exit movement should now be Canceled.
	let exit_movement = bark.history().await.into_iter()
		.find(|m| m.subsystem.name == "bark.exit")
		.expect("exit movement should exist");
	assert_eq!(exit_movement.status, MovementStatus::Canceled);
	assert!(exit_movement.time.completed_at.is_some());
}

/// Walks the exit through its two visible milestones and pins down what the wallet
/// shows at each.
///
/// At `AwaitingDelta` the exit chain has confirmed on-chain. The VTXO must flip to
/// `Exited` (so the wallet — and by extension the server — agrees the VTXO is gone
/// from the protocol's view), drop out of the spendable set, and start contributing
/// to the `pending_exit` balance. The exit movement is still `Pending` because the
/// drain hasn't happened.
///
/// At `Claimed` the drain has confirmed too. The VTXO stays `Exited` (terminal),
/// `pending_exit` drops to zero (it's now in the onchain balance, not pending), and
/// the exit movement flips to `Successful`.
#[tokio::test]
async fn exited_vtxo_is_not_spendable() {
	require_bark_version!(> "0.2.5");

	let ctx = TestContext::new("exit/exited_vtxo_is_not_spendable").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	let exit_amount = sat(500_000);
	bark.board_and_confirm_and_register(&ctx, exit_amount).await;
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	let exited_id = vtxos[0].id;

	// Drive the exit until every exit transaction has confirmed onchain.
	bark.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &bark).await;

	// At this point the chain has accepted the exit chain. The VTXO must be Exited.
	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1);
	assert_eq!(exits[0].vtxo_id, exited_id);
	assert!(matches!(exits[0].state, ExitState::AwaitingDelta(_)),
		"exit should be in AwaitingDelta, got {:?}", exits[0].state);

	// The wallet stops surfacing the VTXO as spendable …
	assert_eq!(bark.vtxos().await.len(), 0,
		"exited vtxo should drop out of the spendable list once its chain confirms");
	let balance = bark.offchain_balance().await;
	assert_eq!(balance.spendable, Amount::ZERO,
		"offchain spendable balance should be zero once the vtxo has exited");
	// … and the amount surfaces under `pending_exit` instead.
	assert_eq!(balance.pending_exit, Some(exit_amount),
		"pending_exit should reflect the exited (but not yet drained) vtxo");

	// The exit movement is still in flight — drain hasn't happened.
	let exit_movement = bark.history().await.into_iter()
		.find(|m| m.subsystem.name == "bark.exit")
		.expect("exit movement should exist");
	assert_eq!(exit_movement.status, MovementStatus::Pending);
	assert!(exit_movement.time.completed_at.is_none());

	// Walk past the CSV delta, drain, confirm, and let progress notice.
	complete_exit(&ctx, &bark).await;
	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;
	bark.progress_exit().await;

	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1);
	assert_eq!(exits[0].vtxo_id, exited_id);
	assert!(matches!(exits[0].state, ExitState::Claimed(_)),
		"exit should be in Claimed, got {:?}", exits[0].state);

	// VTXO is still out of the spendable set (Exited is terminal). `pending_exit`
	// drops to zero because the funds are now onchain via the drain.
	let balance = bark.offchain_balance().await;
	assert_eq!(bark.vtxos().await.len(), 0,
		"exited vtxo should still be out of the spendable list after claim");
	assert_eq!(balance.spendable, Amount::ZERO);
	assert_eq!(balance.pending_exit, Some(Amount::ZERO),
		"pending_exit should drop to zero once the drain has confirmed");

	let exit_movement = bark.history().await.into_iter()
		.find(|m| m.subsystem.name == "bark.exit")
		.expect("exit movement should exist");
	assert_eq!(exit_movement.status, MovementStatus::Successful);
}

/// A wallet must detect when one of its spendable VTXOs has been exited on-chain without the
/// wallet initiating the exit — e.g. the server's watchman progressing a shared tree, or a third
/// party's unilateral exit — and route it into the claimable exit flow so the funds can be
/// recovered.
///
/// Here a stale clone performs the on-chain exit; the original wallet never asked for it. A plain
/// sync must notice the VTXO's funding tx is on-chain and start exiting it, after which the wallet
/// can complete and claim it.
#[tokio::test]
async fn detect_and_claim_force_exited_vtxo() {
	require_bark_version!(> "0.2.5");
	require_bitcoind_chain_source!();

	let ctx = TestContext::new("bark/detect_and_claim_force_exited_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let bark = ctx.bark("bark", &srv).funded(sat(1_000_000)).create().await;

	// Board and refresh into a round vtxo. Exiting it lands its point (the round-tree leaf
	// output) on-chain, which is exactly what the detection looks for.
	bark.board_and_confirm_and_register(&ctx, sat(300_000)).await;
	ctx.refresh_all(&srv, &[&bark]).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	bark.sync().await;
	let before_exit = {
		let vtxos = bark.vtxos().await;
		assert_eq!(vtxos.len(), 1, "bark should hold one round vtxo");
		assert!(matches!(vtxos[0].state, VtxoStateInfo::Spendable));
		vtxos
	};

	// A stale clone exits the vtxo on-chain. The original `bark` never initiated this exit.
	let evil = bark.full_clone("evil").await;
	evil.start_exit_all().await;
	progress_exit_until_awaiting_delta(&ctx, &evil).await;

	// Before detection (no sync), the original still believes the vtxo is spendable.
	assert!(bark.vtxos_no_sync().await.iter()
			.all(|v| before_exit.contains(v) && v.state == VtxoStateInfo::Spendable),
		"vtxo should still look spendable before detection",
	);

	// A plain sync must detect the on-chain exit and route the vtxo into the exit flow.
	bark.sync().await;

	// After detection, no spendable vtxos should exist.
	let exits = bark.list_exits_no_sync().await;
	assert!(exits.iter()
		.all(|ex| before_exit.iter().any(|v| v.id == ex.vtxo_id)),
		"exits should include the original VTXOs",
	);
	assert!(bark.vtxos_no_sync().await.is_empty(), "VTXOs shouldn't be spendable");

	// Complete and claim the exit; the wallet recovers the force-exited funds on-chain. Claim to
	// a bitcoind-owned address so we can assert the funds arrived via `getreceivedbyaddress`.
	complete_exit(&ctx, &bark).await;
	let address = ctx.bitcoind().get_new_address();
	bark.claim_all_exits(address.clone()).await;
	ctx.generate_blocks(1).await;

	let balance = bark.onchain_balance().await;
	assert_eq!(balance, sat(696_053), "wallet should have recovered the force-exited vtxos");
}
