use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use ark::offboard::OffboardRequest;
use ark::{VtxoId, VtxoPolicy};
use ark::lightning::{Invoice, PaymentHash, Preimage};
use bark_json::cli::{MovementDestination, MovementStatus, PaymentMethod};
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Address, Amount, OutPoint, Transaction, Txid, Weight};
use bitcoin::params::Params;
use tokio::join;
use bitcoin_ext::TaprootSpendInfoExt;

use ark_testing::{btc, sat, signed_sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::util::FutureExt;

fn assert_vec_unsorted_equal(mut a: Vec<VtxoId>, mut b: Vec<VtxoId>) {
	a.sort();
	b.sort();
	assert_eq!(a, b);
}

#[tokio::test]
async fn arkoor_send_receive() {
	let ctx = TestContext::new("movement/arkoor_send_receive").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	bark1.board(sat(100_000)).await;
	bark1.board(sat(100_000)).await;
	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark1.maintain().await;

	// Send funds using three VTXOs.
	let bark1_vtxos_pre_pay = bark1.vtxo_ids().await;
	let bark2_addr = bark2.address().await;
	bark1.send_oor(&bark2_addr, sat(230_000)).await;
	let bark1_vtxos_post_pay = bark1.vtxo_ids().await;
	let bark2_vtxos = bark2.vtxo_ids().await;

	let send_movement = bark1.history().await.last().cloned().unwrap();
	assert_eq!(send_movement.status, MovementStatus::Successful);
	assert_eq!(send_movement.subsystem.name, "bark.arkoor");
	assert_eq!(send_movement.subsystem.kind, "send");
	assert_eq!(send_movement.intended_balance, signed_sat(-230_000));
	assert_eq!(send_movement.effective_balance, signed_sat(-230_000));
	assert_eq!(send_movement.offchain_fee, sat(0));
	assert_eq!(send_movement.sent_to.len(), 1);
	assert_eq!(send_movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Ark(bark2_addr.to_string()),
		amount: sat(230_000),
	});
	assert_eq!(send_movement.received_on.len(), 0);
	assert_eq!(send_movement.input_vtxos.len(), 3);
	assert_vec_unsorted_equal(send_movement.input_vtxos, bark1_vtxos_pre_pay);
	assert_eq!(send_movement.output_vtxos.len(), 1);
	assert_eq!(send_movement.output_vtxos, bark1_vtxos_post_pay);
	assert_eq!(send_movement.exited_vtxos.len(), 0);
	assert_eq!(send_movement.time.completed_at.is_some(), true);
	assert_eq!(send_movement.metadata, None);

	let receive_movement = bark2.history().await.last().cloned().unwrap();
	assert_eq!(receive_movement.status, MovementStatus::Successful);
	assert_eq!(receive_movement.subsystem.name, "bark.arkoor");
	assert_eq!(receive_movement.subsystem.kind, "receive");
	assert_eq!(receive_movement.intended_balance, signed_sat(230_000));
	assert_eq!(receive_movement.effective_balance, signed_sat(230_000));
	assert_eq!(receive_movement.offchain_fee, sat(0));
	assert_eq!(receive_movement.sent_to.len(), 0);
	assert_eq!(receive_movement.received_on.len(), 0); // We don't know the address an arkoor was sent to.
	assert_eq!(receive_movement.input_vtxos.len(), 0);
	assert_eq!(receive_movement.output_vtxos.len(), 3);
	assert_vec_unsorted_equal(receive_movement.output_vtxos, bark2_vtxos);
	assert_eq!(receive_movement.exited_vtxos.len(), 0);
	assert_eq!(receive_movement.time.completed_at.is_some(), true);
	assert_eq!(receive_movement.metadata, None);
}

#[tokio::test]
async fn board_board() {
	let ctx = TestContext::new("movement/board_board").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let vtxos = bark.vtxo_ids().await;
	assert_eq!(vtxos.len(), 1);

	let movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(movement.status, MovementStatus::Successful);
	assert_eq!(movement.subsystem.name, "bark.board");
	assert_eq!(movement.subsystem.kind, "board");
	assert_eq!(movement.intended_balance, signed_sat(100_000));
	assert_eq!(movement.effective_balance, signed_sat(100_000));
	assert_eq!(movement.offchain_fee, sat(0));
	assert_eq!(movement.sent_to.len(), 0);
	assert_eq!(movement.received_on.len(), 0);
	assert_eq!(movement.input_vtxos.len(), 0);
	assert_eq!(movement.output_vtxos.len(), 1);
	assert_eq!(movement.output_vtxos, vtxos);
	assert_eq!(movement.exited_vtxos.len(), 0);
	assert_eq!(movement.time.completed_at.is_some(), true);

	assert_eq!(movement.metadata.is_some(), true);
	let metadata = movement.metadata.as_ref().unwrap();

	let onchain_fee_sat = metadata.get("onchain_fee_sat").map(|f| serde_json::from_value::<Amount>(f.clone()).unwrap());
	assert_eq!(onchain_fee_sat, Some(sat(772)));
	assert_eq!(
		metadata.get("chain_anchor").map(|ca| serde_json::from_value::<OutPoint>(ca.clone()).unwrap()).is_some(),
		true,
	);
}

#[tokio::test]
async fn exit_start() {
	let ctx = TestContext::new("movement/exit_start").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	bark.start_exit_all().await;
	let exits = bark.list_exits().await;
	assert_eq!(exits.len(), 1);
	assert_eq!(exits.first().unwrap().vtxo_id, vtxos.first().unwrap().vtxo.id);

	let movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(movement.status, MovementStatus::Successful);
	assert_eq!(movement.subsystem.name, "bark.exit");
	assert_eq!(movement.subsystem.kind, "start");
	assert_eq!(movement.intended_balance, signed_sat(-100_000));
	assert_eq!(movement.effective_balance, signed_sat(-100_000));
	assert_eq!(movement.offchain_fee, sat(0));
	assert_eq!(movement.sent_to.len(), 1);
	assert_eq!(movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Bitcoin({
			let v = vtxos.first().unwrap();
			let exit_spk = VtxoPolicy::new_pubkey(v.user_pubkey)
				.taproot(v.server_pubkey, v.exit_delta, v.expiry_height)
				.script_pubkey();
			Address::from_script(&exit_spk, Params::REGTEST).unwrap().to_string()
		}),
		amount: sat(100_000),
	});
	assert_eq!(movement.received_on.len(), 0);
	assert_eq!(movement.input_vtxos.len(), 1);
	assert_eq!(*movement.input_vtxos.first().unwrap(), vtxos.first().unwrap().id);
	assert_eq!(movement.output_vtxos.len(), 0);
	assert_eq!(movement.exited_vtxos.len(), 0);
	assert_eq!(movement.time.completed_at.is_some(), true);
	assert_eq!(movement.metadata.is_none(), true);
}

#[tokio::test]
async fn lightning_send_invoice_receive() {
	let ctx = TestContext::new("movement/lightning_send_invoice_receive").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.new_captaind_with_funds("server", Some(&ln.sender), btc(10)).await;
	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = Arc::new(ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await);

	bark1.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let bark1_vtxos = bark1.vtxo_ids().await;

	// Verify movements don't exist until a payment is initiated. bark1 will have a board movement.
	assert_eq!(bark1.history().await.len(), 1);
	assert_eq!(bark2.history().await.len(), 0);

	let invoice = Invoice::from_str(&bark2.bolt11_invoice(sat(10_000)).await.invoice).unwrap();
	assert_eq!(bark2.history().await.len(), 0);
	let bark2_clone = bark2.clone();
	srv.wait_for_vtxopool(&ctx).await;
	join!(
		bark1.pay_lightning_wait(&invoice, None),
		async move {
			bark2_clone.lightning_receive_all().wait_millis(60_000).await;
		},
	);

	let send_movement = bark1.history().await.last().cloned().unwrap();
	assert_eq!(send_movement.status, MovementStatus::Successful);
	assert_eq!(send_movement.subsystem.name, "bark.lightning_send");
	assert_eq!(send_movement.subsystem.kind, "send");
	assert_eq!(send_movement.intended_balance, signed_sat(-10_000));
	assert_eq!(send_movement.effective_balance, signed_sat(-10_000));
	assert_eq!(send_movement.offchain_fee, sat(0));
	assert_eq!(send_movement.sent_to.len(), 1);
	assert_eq!(send_movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: sat(10_000),
	});
	assert_eq!(send_movement.received_on.len(), 0);
	assert_eq!(send_movement.input_vtxos.len(), 1);
	assert_eq!(send_movement.input_vtxos, bark1_vtxos);
	assert_eq!(send_movement.output_vtxos.len(), 1); // HTLC VTXOs aren't included here
	assert_ne!(send_movement.output_vtxos, bark1_vtxos);
	assert_eq!(send_movement.exited_vtxos.len(), 0);
	assert_eq!(send_movement.time.completed_at.is_some(), true);

	assert_eq!(send_movement.metadata.is_some(), true);
	let metadata = send_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap().len(), 1);
	let payment_preimage = metadata.get("payment_preimage").map(|preimage| serde_json::from_value::<Preimage>(preimage.clone()).unwrap()).unwrap();
	assert_eq!(payment_hash, Some(payment_preimage.compute_payment_hash()));

	let bark2_vtxos = bark2.vtxo_ids().await;
	let receive_movement = bark2.history().await.last().cloned().unwrap();
	assert_eq!(receive_movement.status, MovementStatus::Successful);
	assert_eq!(receive_movement.subsystem.name, "bark.lightning_receive");
	assert_eq!(receive_movement.subsystem.kind, "receive");
	assert_eq!(receive_movement.intended_balance, signed_sat(10_000));
	assert_eq!(receive_movement.effective_balance, signed_sat(10_000));
	assert_eq!(receive_movement.offchain_fee, sat(0));
	assert_eq!(receive_movement.sent_to.len(), 0);
	assert_eq!(receive_movement.received_on.len(), 1);
	assert_eq!(receive_movement.received_on.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: sat(10_000),
	});
	assert_eq!(receive_movement.input_vtxos.len(), 0);
	assert_eq!(receive_movement.output_vtxos.len(), 1); // HTLC VTXOs aren't included here
	assert_eq!(receive_movement.output_vtxos, bark2_vtxos);
	assert_eq!(receive_movement.exited_vtxos.len(), 0);
	assert_eq!(receive_movement.time.completed_at.is_some(), true);

	assert_eq!(receive_movement.metadata.is_some(), true);
	let metadata = receive_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap().len(), 1);
	let payment_preimage = metadata.get("payment_preimage").map(|preimage| serde_json::from_value::<Preimage>(preimage.clone()).unwrap()).unwrap();
	assert_eq!(payment_hash, Some(payment_preimage.compute_payment_hash()));
}

#[tokio::test]
async fn lightning_send_invoice_revoke() {
	let ctx = TestContext::new("movement/lightning_send_invoice_revoke").await;
	let ln = ctx.new_lightning_setup_no_channel("ln").await;
	let srv = ctx.new_captaind_with_funds("server", Some(&ln.sender), btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	let vtxos_pre_pay = bark.vtxo_ids().await;

	// Verify movements don't exist until a payment is initiated. bark1 will have a board movement.
	assert_eq!(bark.history().await.len(), 1);

	let invoice = Invoice::from_str(
		&ln.receiver.invoice(Some(sat(10_000)), "movement_send_fail", "will fail").await,
	).unwrap();
	srv.wait_for_vtxopool(&ctx).await;
	bark.pay_lightning_wait(&invoice, None).await;
	let vtxos_post_pay = bark.vtxo_ids().await;

	let send_movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(send_movement.status, MovementStatus::Failed);
	assert_eq!(send_movement.subsystem.name, "bark.lightning_send");
	assert_eq!(send_movement.subsystem.kind, "send");
	assert_eq!(send_movement.intended_balance, signed_sat(-10_000));
	assert_eq!(send_movement.effective_balance, signed_sat(0));
	assert_eq!(send_movement.offchain_fee, sat(0));
	assert_eq!(send_movement.sent_to.len(), 1);
	assert_eq!(send_movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Invoice(invoice.to_string()),
		amount: sat(10_000),
	});
	assert_eq!(send_movement.received_on.len(), 0);
	assert_eq!(send_movement.input_vtxos.len(), 1);
	assert_eq!(send_movement.input_vtxos, vtxos_pre_pay);
	assert_eq!(send_movement.output_vtxos.len(), 2); // Change + revocation VTXO
	assert_vec_unsorted_equal(send_movement.output_vtxos, vtxos_post_pay);
	assert_eq!(send_movement.exited_vtxos.len(), 0);
	assert_eq!(send_movement.time.completed_at.is_some(), true);

	assert_eq!(send_movement.metadata.is_some(), true);
	let metadata = send_movement.metadata.as_ref().unwrap();
	let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap());
	assert_eq!(payment_hash, Some(invoice.payment_hash()));
	assert_eq!(metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap().len(), 1);
}

#[tokio::test]
async fn lightning_send_offer() {
	let ctx = TestContext::new("movement/lightning_send_offer").await;
	let ln = ctx.new_lightning_setup("ln").await;
	let srv = ctx.new_captaind_with_funds("server", Some(&ln.sender), btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	bark.board_and_confirm_and_register(&ctx, sat(500_000)).await;

	// Verify movements don't exist until a payment is initiated. bark1 will have a board movement.
	assert_eq!(bark.history().await.len(), 1);

	let mut payment_hashes = HashSet::<PaymentHash>::new();
	let mut htlc_vtxos = HashSet::<VtxoId>::new();
	let offer = ln.receiver.offer(None, Some("movement_offer")).await;
	ln.sync().await;
	srv.wait_for_vtxopool(&ctx).await;
	for i in 1..5 {
		let amount = sat(i * 10_000);
		let vtxos_pre_pay = bark.vtxo_ids().await;
		bark.pay_lightning_wait(&offer, Some(amount)).await;

		let movement = bark.history().await.last().cloned().unwrap();
		assert_eq!(movement.status, MovementStatus::Successful);
		assert_eq!(movement.subsystem.name, "bark.lightning_send");
		assert_eq!(movement.subsystem.kind, "send");
		assert_eq!(movement.intended_balance, -amount.to_signed().unwrap());
		assert_eq!(movement.effective_balance, -amount.to_signed().unwrap());
		assert_eq!(movement.offchain_fee, sat(0));
		assert_eq!(movement.sent_to.len(), 1);
		assert_eq!(movement.sent_to.first().unwrap(), &MovementDestination {
			destination: PaymentMethod::Offer(offer.clone()),
			amount,
		});
		assert_eq!(movement.received_on.len(), 0);
		assert_eq!(movement.input_vtxos.len(), 1);
		assert_eq!(movement.input_vtxos, vtxos_pre_pay);
		assert_eq!(movement.output_vtxos.len(), 1);
		assert_ne!(movement.output_vtxos, vtxos_pre_pay);
		assert_eq!(movement.exited_vtxos.len(), 0);
		assert_eq!(movement.time.completed_at.is_some(), true);

		assert_eq!(movement.metadata.is_some(), true);
		let metadata = movement.metadata.as_ref().unwrap();
		let payment_hash = metadata.get("payment_hash").map(|ph| serde_json::from_value::<PaymentHash>(ph.clone()).unwrap()).unwrap();
		assert_eq!(payment_hashes.insert(payment_hash), true, "Payment hashes should be unique");

		let htlc_vtxo_ids = metadata.get("htlc_vtxos").map(|v| serde_json::from_value::<Vec<VtxoId>>(v.clone()).unwrap()).unwrap();
		for vtxo_id in htlc_vtxo_ids {
			assert_eq!(htlc_vtxos.insert(vtxo_id), true, "HTLC VTXO IDs should be unique");
		}
	}
}

#[tokio::test]
async fn movement_offboard() {
	let ctx = TestContext::new("movement/movement_offboard").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(100_000)).await;
	bark.board(sat(100_000)).await;
	bark.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.maintain().await;

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 3);
	let addr = bark.get_onchain_address().await;
	let offb_vtxo = vtxos.first().unwrap();
	let offboard = bark.offboard_vtxo(offb_vtxo.id, &addr).await;

	let expected_fee = OffboardRequest::calculate_fee(
		&addr.script_pubkey(),
		srv.config().offboard_feerate,
		Weight::from_vb_unchecked(srv.config().offboard_fixed_fee_vb),
	).unwrap();

	let movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(movement.status, MovementStatus::Successful);
	assert_eq!(movement.subsystem.name, "bark.offboard");
	assert_eq!(movement.subsystem.kind, "offboard");
	assert_eq!(movement.intended_balance, -offb_vtxo.amount.to_signed().unwrap());
	assert_eq!(movement.effective_balance, -offb_vtxo.amount.to_signed().unwrap());
	assert_eq!(movement.offchain_fee, expected_fee);
	assert_eq!(movement.sent_to.len(), 1);
	assert_eq!(movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Bitcoin(addr.to_string()),
		amount: offb_vtxo.amount - expected_fee,
	});
	assert_eq!(movement.received_on.len(), 0);
	assert_eq!(movement.input_vtxos.len(), 1);
	assert_eq!(*movement.input_vtxos.first().unwrap(), offb_vtxo.id);
	assert_eq!(movement.output_vtxos.len(), 0);
	assert_eq!(movement.exited_vtxos.len(), 0);
	assert_eq!(movement.time.completed_at.is_some(), true);

	assert_eq!(movement.metadata.is_some(), true);
	assert_eq!(offboard.offboard_txid,
		movement.metadata.as_ref().unwrap().get("offboard_txid")
			.map(|txid| serde_json::from_value::<Txid>(txid.clone()).unwrap()).unwrap(),
	);
	assert_eq!(offboard.offboard_txid,
		deserialize_hex::<Transaction>(&movement.metadata.as_ref().unwrap().get("offboard_tx")
			.map(|hex| serde_json::from_value::<String>(hex.clone()).unwrap()).unwrap()
		).unwrap().compute_txid(),
	);
}

#[tokio::test]
async fn round_refresh() {
	let ctx = TestContext::new("movement/round_refresh").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board(sat(100_000)).await;
	bark.board(sat(100_000)).await;
	bark.board(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.maintain().await;

	let vtxos_pre_refresh = bark.vtxo_ids().await;
	assert_eq!(vtxos_pre_refresh.len(), 3);
	bark.refresh_all().await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	let vtxos_post_refresh = bark.vtxo_ids().await;

	let movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(movement.status, MovementStatus::Successful);
	assert_eq!(movement.subsystem.name, "bark.round");
	assert_eq!(movement.subsystem.kind, "refresh");
	assert_eq!(movement.intended_balance, signed_sat(0));
	assert_eq!(movement.effective_balance, signed_sat(0));
	assert_eq!(movement.offchain_fee, sat(0));
	assert_eq!(movement.sent_to.len(), 0);
	assert_eq!(movement.received_on.len(), 0);
	assert_eq!(movement.input_vtxos.len(), 3);
	assert_vec_unsorted_equal(movement.input_vtxos, vtxos_pre_refresh);
	assert_eq!(movement.output_vtxos.len(), 1);
	assert_eq!(movement.output_vtxos, vtxos_post_refresh);
	assert_eq!(movement.exited_vtxos.len(), 0);
	assert_eq!(movement.time.completed_at.is_some(), true);

	assert_eq!(movement.metadata.is_some(), true);
	movement.metadata.as_ref().unwrap().get("funding_txid")
		.map(|txid| serde_json::from_value::<Txid>(txid.clone()).unwrap()).unwrap();
}

#[tokio::test]
async fn movement_send_onchain() {
	let ctx = TestContext::new("movement/movement_send_onchain").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(1_000_000)).await;

	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	// 1 consumed VTXO and 1 change VTXO
	let vtxos_pre_send = bark.vtxo_ids().await;
	let addr = bark.get_onchain_address().await;
	let amount = sat(50_000);
	let offboard = bark.send_onchain(&addr, amount).await;
	ctx.generate_blocks(2).await;
	let vtxos_post_send = bark.vtxo_ids().await;

	let expected_fee = OffboardRequest::calculate_fee(
		&addr.script_pubkey(),
		srv.config().offboard_feerate,
		Weight::from_vb_unchecked(srv.config().offboard_fixed_fee_vb as u64),
	).unwrap();

	let movement = bark.history().await.last().cloned().unwrap();
	assert_eq!(movement.status, MovementStatus::Successful);
	assert_eq!(movement.subsystem.name, "bark.offboard");
	assert_eq!(movement.subsystem.kind, "send_onchain");
	assert_eq!(movement.intended_balance, -amount.to_signed().unwrap());
	assert_eq!(movement.effective_balance, -(amount + expected_fee).to_signed().unwrap());
	assert_eq!(movement.offchain_fee, expected_fee);
	assert_eq!(movement.sent_to.len(), 1);
	assert_eq!(movement.sent_to.first().unwrap(), &MovementDestination {
		destination: PaymentMethod::Bitcoin(addr.to_string()),
		amount: amount,
	});
	assert_eq!(movement.received_on.len(), 0);
	assert_eq!(movement.input_vtxos.len(), 1);
	assert_eq!(movement.input_vtxos, vtxos_pre_send);
	assert_eq!(movement.output_vtxos.len(), 1);
	assert_eq!(movement.output_vtxos, vtxos_post_send);
	assert_eq!(movement.exited_vtxos.len(), 0);
	assert_eq!(movement.time.completed_at.is_some(), true);

	assert_eq!(movement.metadata.is_some(), true);
	assert_eq!(offboard.offboard_txid,
		movement.metadata.as_ref().unwrap().get("offboard_txid")
			.map(|txid| serde_json::from_value::<Txid>(txid.clone()).unwrap()).unwrap(),
	);
	assert_eq!(offboard.offboard_txid,
		deserialize_hex::<Transaction>(&movement.metadata.as_ref().unwrap().get("offboard_tx")
			.map(|hex| serde_json::from_value::<String>(hex.clone()).unwrap()).unwrap()
		).unwrap().compute_txid(),
	);
}
