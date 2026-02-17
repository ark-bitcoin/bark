use std::sync::Arc;
use std::time::Duration;

use bitcoin::{Amount, FeeRate};

use ark::fees::{
	BoardFees, LightningReceiveFees, LightningSendFees, OffboardFees, PpmExpiryFeeEntry,
	PpmFeeRate, RefreshFees,
};
use bark_json::cli::{MovementDestination, PaymentMethod};
use bitcoin_ext::FeeRateExt;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::{BOARD_CONFIRMATIONS, ROUND_CONFIRMATIONS};
use ark_testing::exit::complete_exit;
use ark_testing::util::{FutureExt, ToAltString};

#[tokio::test]
async fn exit_fee_anchor_only_covers_cost() {
	let ctx = TestContext::new("exit/exit_fee_anchor_only_covers_cost").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: sat(10_000),
			base_fee: Amount::ZERO,
			ppm: PpmFeeRate::ZERO,
		};
	}).await;
	let bark = ctx.try_new_bark_with_cfg("bark1".to_string(), &srv, |cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_kvb_ceil(100));
	}).await.unwrap();
	ctx.fund_captaind(&srv, btc(1)).await;
	ctx.fund_bark(&bark, sat(100_013)).await;
	ctx.generate_blocks(1).await;

	bark.board_all().await;
	ctx.fund_bark(&bark, sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	// Bark should have 1 UTXO of 100,000 sats and 1 VTXO of 90,000 sats.
	let vtxos = bark.vtxos().await;
	let utxos = bark.utxos().await;
	assert_eq!(vtxos.len(), 1, "We should have one vtxo");
	assert_eq!(utxos.len(), 1, "We should have one utxo");
	assert_eq!(vtxos[0].amount, sat(90_000), "VTXO amount is incorrect");
	assert_eq!(utxos[0].amount, sat(100_000), "UTXO amount is incorrect");
	srv.stop().await.unwrap();

	// Exit the board VTXO, it should have a fee anchor with enough to cover the entire exit.
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Verify the exited amount.
	assert_eq!(bark.vtxos().await.len(), 0);
	let utxos = bark.utxos().await;
	assert_eq!(utxos.len(), 3);
	assert!(utxos.iter().any(|u| u.amount == sat(100_000))); // Untouched UTXO
	assert!(utxos.iter().any(|u| u.amount == sat(89_987))); // Exited UTXO (minus claim fees)
	assert!(utxos.iter().any(|u| u.amount == sat(9_978))); // Fee anchor change
}

#[tokio::test]
async fn exit_fee_anchor_no_dust_change_error() {
	let ctx = TestContext::new("exit/exit_fee_anchor_no_dust_change_error").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: sat(330),
			base_fee: Amount::ZERO,
			ppm: PpmFeeRate::ZERO,
		};
	}).await;
	let bark = ctx.try_new_bark_with_cfg("bark1".to_string(), &srv, |cfg| {
		cfg.fallback_fee_rate = Some(FeeRate::from_sat_per_kvb_ceil(100));
	}).await.unwrap();
	ctx.fund_captaind(&srv, btc(1)).await;
	ctx.fund_bark(&bark, sat(100_013)).await;
	ctx.generate_blocks(1).await;

	bark.board_all().await;
	ctx.fund_bark(&bark, sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;

	// Bark should have 1 UTXO of 100,000 sats and 1 VTXO of 99,670 sats.
	let _ = bark.history().await;
	let vtxos = bark.vtxos().await;
	let utxos = bark.utxos().await;
	assert_eq!(vtxos.len(), 1, "We should have one vtxo");
	assert_eq!(utxos.len(), 1, "We should have one utxo");
	assert_eq!(vtxos[0].amount, sat(99_670), "VTXO amount is incorrect");
	assert_eq!(utxos[0].amount, sat(100_000), "UTXO amount is incorrect");
	srv.stop().await.unwrap();

	// Exit the board VTXO, the fee anchor value minus the exit fee should be dust; therefore, the
	// fee anchor should be spent in its entirety.
	bark.start_exit_all().await;
	complete_exit(&ctx, &bark).await;

	bark.claim_all_exits(bark.get_onchain_address().await).await;
	ctx.generate_blocks(1).await;

	// Verify the exited amount.
	assert_eq!(bark.vtxos().await.len(), 0);
	let utxos = bark.utxos().await;
	assert_eq!(utxos.len(), 2);
	assert!(utxos.iter().any(|u| u.amount == sat(99_999))); // Unboarded + fee anchor change
	assert!(utxos.iter().any(|u| u.amount == sat(99_657))); // Exited amount
}

#[tokio::test]
async fn board_fee_base_and_ppm() {
	let ctx = TestContext::new("fees/board_fee_base_and_ppm").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: Amount::ZERO,
			base_fee: sat(100),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	// Fee = base(100) + 100,000 * 10,000 / 1,000,000 = 100 + 1,000 = 1,100
	let expected_fee = sat(1_100);
	let expected_vtxo_amount = sat(100_000) - expected_fee;

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	assert_eq!(vtxos[0].amount, expected_vtxo_amount,
		"VTXO amount should be board amount minus fee");

	let movements = bark.history().await;
	assert_eq!(movements.len(), 1);
	let board_mvt = &movements[0];
	assert_eq!(board_mvt.offchain_fee, expected_fee);
	assert_eq!(board_mvt.intended_balance, sat(100_000).to_signed().unwrap());
	assert_eq!(board_mvt.effective_balance, expected_vtxo_amount.to_signed().unwrap());
}

#[tokio::test]
async fn board_fee_min_fee_applies() {
	let ctx = TestContext::new("fees/board_fee_min_fee_applies").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: sat(5_000),
			base_fee: Amount::ZERO,
			ppm: PpmFeeRate::ZERO,
		};
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	// Fee = max(5,000, 0 + 0) = 5,000
	let expected_fee = sat(5_000);
	let expected_vtxo_amount = sat(95_000);

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1);
	assert_eq!(vtxos[0].amount, expected_vtxo_amount);

	let movements = bark.history().await;
	assert_eq!(movements.len(), 1);
	assert_eq!(movements[0].offchain_fee, expected_fee);
	assert_eq!(movements[0].effective_balance, expected_vtxo_amount.to_signed().unwrap());
}

#[tokio::test]
async fn board_fee_rejects_when_fee_exceeds_amount() {
	let ctx = TestContext::new("fees/board_fee_rejects_when_fee_exceeds_amount").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.board = BoardFees {
			min_fee: sat(50_000),
			base_fee: Amount::ZERO,
			ppm: PpmFeeRate::ZERO,
		};
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// Board 30,000 sats (above min_board_amount=20,000 but fee=50,000 > amount)
	let err = bark.try_board(sat(50_000)).await.unwrap_err();
	assert!(
		err.to_alt_string().contains("exceeds amount"),
		"Expected fee exceeds amount error, got: {:#}", err,
	);

	// Balance should be unchanged - no VTXOs created
	assert_eq!(bark.vtxos().await.len(), 0);
}

#[tokio::test]
async fn refresh_fee_base_only() {
	let ctx = TestContext::new("fees/refresh_fee_base_only").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(1_000),
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;
	assert_eq!(bark.spendable_balance().await, sat(100_000));

	ctx.refresh_all(&srv, std::slice::from_ref(&bark)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// After refresh, balance should be reduced by base_fee
	let expected_fee = sat(1_000);
	assert_eq!(bark.spendable_balance().await, sat(99_000));

	let movements = bark.history().await;
	assert_eq!(movements.len(), 2); // board + refresh
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.offchain_fee, expected_fee);
	assert_eq!(refresh_mvt.effective_balance, -expected_fee.to_signed().unwrap());
}

#[tokio::test]
async fn refresh_fee_with_ppm_expiry() {
	let ctx = TestContext::new("fees/refresh_fee_with_ppm_expiry").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(200),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 50, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	// VTXOs have ~134-140 blocks until expiry (vtxo_lifetime=144 minus blocks generated).
	// This exceeds the 50-block threshold, so 1% ppm applies.
	// Fee = base(200) + 100,000 * 10,000 / 1,000,000 = 200 + 1,000 = 1,200
	let expected_fee = sat(1_200);
	ctx.refresh_all(&srv, std::slice::from_ref(&bark)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;
	assert_eq!(bark.spendable_balance().await, sat(100_000) - expected_fee);

	let movements = bark.history().await;
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.offchain_fee, expected_fee);
	assert_eq!(refresh_mvt.effective_balance, -expected_fee.to_signed().unwrap());
}

#[tokio::test]
async fn refresh_fee_with_multiple_vtxos() {
	let ctx = TestContext::new("fees/refresh_fee_with_multiple_vtxos").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(500),
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// Board three separate VTXOs
	bark.board(sat(100_000)).await;
	bark.board(sat(200_000)).await;
	bark.board(sat(300_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	bark.sync().await;
	assert_eq!(bark.vtxos().await.len(), 3);
	assert_eq!(bark.spendable_balance().await, sat(600_000));

	// Refresh all VTXOs (consolidates into one)
	ctx.refresh_all(&srv, std::slice::from_ref(&bark)).await;
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	// Fee = base_fee only (no ppm entries). Applied once for the whole refresh.
	let expected_fee = sat(500);
	assert_eq!(bark.spendable_balance().await, sat(600_000) - expected_fee);

	let vtxos = bark.vtxos().await;
	assert_eq!(vtxos.len(), 1, "VTXOs should be consolidated into one");
	assert_eq!(vtxos[0].amount, sat(599_500));

	let movements = bark.history().await;
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.offchain_fee, expected_fee);
	assert_eq!(refresh_mvt.effective_balance, -expected_fee.to_signed().unwrap());
}

#[tokio::test]
async fn refresh_should_refresh_vtxos() {
	let ctx = TestContext::new("fees/refresh_should_refresh_vtxos").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.vtxo_lifetime = 144;
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(500),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;

	// Board VTXO A
	bark.board(sat(100_000)).await;
	ctx.generate_blocks(10).await;

	// Board VTXO B
	bark.board(sat(200_000)).await;
	ctx.generate_blocks(50).await;
	assert_eq!(bark.vtxos().await.len(), 2);

	// Board VTXO C
	bark.board_and_confirm_and_register(&ctx, sat(300_000)).await;

	let vtxos = bark.vtxos().await;
	let vtxo = vtxos.iter().find(|v| v.amount == sat(300_000)).unwrap();
	let id = vtxo.id.to_string();
	assert_eq!(bark.vtxos().await.len(), 3);
	assert_eq!(bark.spendable_balance().await, sat(600_000));

	// Advance 60 more blocks so that:
	// - VTXO A is in must_refresh zone (blocks_left < 24)
	// - VTXO B is in should_refresh zone (24 < blocks_left < 52)
	// - VTXO C is not in any refresh zone (blocks_left > 52)
	ctx.generate_blocks(60).await;
	let (_, result) = tokio::join!(
		srv.trigger_round(),
		bark.try_run(["refresh", "--vtxo", id.as_str()]),
	);
	result.expect("refresh command failed");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let vtxos = bark.vtxos().await;
	assert_eq!(
		vtxos.len(), 2, "Should have 2 VTXOs: 1 refresh output, 1 should-refresh consolidation",
	);

	let expected_fee = sat(6_500);
	assert_eq!(
		vtxos.iter().filter(|v| v.amount == sat(296_500)).count(), 1,
		"One VTXO which was explicitly refreshed, includes base fee",
	);
	assert_eq!(
		vtxos.iter().filter(|v| v.amount == sat(297_000)).count(), 1,
		"One VTXO which is a consolidation of 100K and 200K VTXOs, excludes base fee",
	);

	// Balance = 296,500 + 297,000 = 593,500
	assert_eq!(bark.spendable_balance().await, sat(600_000) - expected_fee);

	// Verify movement
	let movements = bark.history().await;
	assert_eq!(movements.len(), 4); // 3 boards + 1 refresh
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.offchain_fee, expected_fee);
	assert_eq!(refresh_mvt.effective_balance, -expected_fee.to_signed().unwrap());
}

#[tokio::test]
async fn refresh_should_refresh_vtxos_no_dust() {
	let ctx = TestContext::new("fees/refresh_should_refresh_vtxos_no_dust").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.vtxo_lifetime = 144;
		cfg.fees.refresh = RefreshFees {
			base_fee: Amount::ZERO,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark_with_funds("bark2", &srv, sat(1_000_000)).await;

	// Board VTXO A
	bark1.board(sat(100_000)).await;
	ctx.generate_blocks(100).await;

	// Board VTXO B
	bark2.board(sat(200_000)).await;
	ctx.generate_blocks(50).await;

	// Create VTXO A'
	bark1.send_oor(bark2.address().await, sat(331)).await;

	let bark2_vtxos = bark2.vtxos().await;
	assert_eq!(bark1.vtxos().await.len(), 1);
	assert_eq!(bark2_vtxos.len(), 2);

	let vtxo = bark2_vtxos.iter().find(|v| v.amount == sat(200_000)).unwrap();
	let id = vtxo.id.to_string();
	assert_eq!(bark2.spendable_balance().await, sat(200_331));

	// Advance 60 more blocks so that:
	// - VTXO A' is in must_refresh zone (blocks_left < 24)
	// - VTXO B is not in any refresh zone (blocks_left > 52)
	let (_, result) = tokio::join!(
		srv.trigger_round(),
		bark2.try_run(["refresh", "--vtxo", id.as_str()]),
	);
	result.expect("refresh command failed");
	ctx.generate_blocks(ROUND_CONFIRMATIONS).await;

	let vtxos = bark2.vtxos().await;
	assert_eq!(vtxos.len(), 2, "Should have 2 VTXOs: 1 refresh output, 1 expired VTXO");

	let expected_fee = sat(200_000) * PpmFeeRate::ONE_PERCENT;
	let tip = ctx.bitcoind().get_block_count().await as u32;
	assert_eq!(
		vtxos.iter().filter(|v| v.amount == sat(198_000)).count(), 1,
		"One VTXO which was explicitly refreshed",
	);
	assert_eq!(
		vtxos.iter().filter(|v| v.amount == sat(331) && v.expiry_height < tip).count(), 1,
		"One VTXO which was not consolidated",
	);

	assert_eq!(bark2.spendable_balance().await, sat(200_331) - expected_fee);

	// Verify movement
	let movements = bark2.history().await;
	assert_eq!(movements.len(), 3); // 1 board + 1 arkoor + 1 refresh
	let refresh_mvt = movements.last().unwrap();
	assert_eq!(refresh_mvt.offchain_fee, expected_fee);
	assert_eq!(refresh_mvt.effective_balance, -expected_fee.to_signed().unwrap());
	assert_eq!(refresh_mvt.input_vtxos.len(), 1);
	assert_eq!(refresh_mvt.input_vtxos, vec![vtxo.id]);
}

#[tokio::test]
async fn refresh_fee_rejects_dust_output() {
	let ctx = TestContext::new("fees/refresh_fee_rejects_dust_output").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		// Fee so high that the output would be below dust (330 sats)
		cfg.fees.refresh = RefreshFees {
			base_fee: sat(99_800),
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	// Refresh should fail: output (100,000 - 99,800 = 200) < P2TR_DUST (330)
	let (_, refresh) = tokio::join!(
		srv.trigger_round(),
		bark.try_refresh_all_no_retry(),
	);
	let err = refresh.unwrap_err();
	assert!(
		err.to_alt_string().contains("dust"),
		"Expected dust error, got: {:#}", err,
	);

	// Balance should be unchanged
	assert_eq!(bark.spendable_balance().await, sat(100_000));
}

#[tokio::test]
async fn offboard_fee_base_deducted() {
	let ctx = TestContext::new("fees/offboard_fee_base_deducted").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.offboard = OffboardFees {
			base_fee: sat(5_000),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(100_000)).await;

	let address = ctx.bitcoind().get_new_address();
	tokio::join!(
		srv.trigger_round(),
		bark.offboard_all(&address),
	);

	assert_eq!(bark.spendable_balance().await, sat(0));

	let movements = bark.history().await;
	let offb_mvt = movements.last().unwrap();

	// Fee includes base_fee (5,000) plus weight fee from fixed_additional_vb * fee_rate
	assert_eq!(offb_mvt.offchain_fee, sat(5_854),
		"offchain fee should be at least base_fee, got {}", offb_mvt.offchain_fee,
	);
	let fee = offb_mvt.offchain_fee;

	assert_eq!(
		offb_mvt.sent_to.first(),
		Some(MovementDestination {
			destination: PaymentMethod::Bitcoin(address.to_string()),
			amount: sat(100_000) - fee,
		}).as_ref(),
	);

	// Verify destination received the correct amount on-chain
	ctx.generate_blocks(1).await;
	let received = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(received, sat(100_000) - fee);
}

#[tokio::test]
async fn offboard_fee_with_ppm_expiry() {
	let ctx = TestContext::new("fees/offboard_fee_with_ppm_expiry").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.fees.offboard = OffboardFees {
			base_fee: Amount::ZERO,
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO },
				PpmExpiryFeeEntry {
					expiry_blocks_threshold: 50, ppm: PpmFeeRate(20_000), // 2%
				},
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(500_000)).await;

	let address = ctx.bitcoind().get_new_address();
	tokio::join!(
		srv.trigger_round(),
		bark.offboard_all(&address),
	);

	let movements = bark.history().await;
	let offb_mvt = movements.last().unwrap();

	// PPM fee on 500,000 at 2% = 10,000, plus weight fee
	assert_eq!(offb_mvt.offchain_fee, sat(10_854),
		"offchain fee should include ppm component, got {}", offb_mvt.offchain_fee,
	);

	ctx.generate_blocks(1).await;
	let received = ctx.bitcoind().get_received_by_address(&address);
	assert_eq!(received, sat(500_000) - offb_mvt.offchain_fee);
}

#[tokio::test]
async fn offboard_all_rejects_dust_output() {
	let ctx = TestContext::new("fees/offboard_all_rejects_dust_output").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.round_interval = Duration::from_secs(3600);
		cfg.offboard_feerate = FeeRate::from_sat_per_vb(7).unwrap();
		cfg.fees.offboard = OffboardFees {
			base_fee: sat(19_600),
			fixed_additional_vb: 0,
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	bark.board_and_confirm_and_register(&ctx, sat(20_000)).await;

	// Offboard fee = base(19,600) + weight_fee(22 vb * 7 sat/vb = 154) = 19,754
	// Amount after fee = 20,000 - 19,754 = 246 < P2TR_DUST (330) → rejected
	let address = ctx.bitcoind().get_new_address();
	let err = bark.try_offboard_all(&address).await.unwrap_err();
	assert!(
		err.to_alt_string().contains("dust"),
		"Expected dust error, got: {:#}", err,
	);

	// Balance should be unchanged
	assert_eq!(bark.spendable_balance().await, sat(20_000));
}

#[tokio::test]
async fn send_onchain_fee_deducted() {
	let ctx = TestContext::new("fees/send_onchain_fee_deducted").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.offboard = OffboardFees {
			base_fee: sat(3_000),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark1 = ctx.new_bark_with_funds("bark1", &srv, sat(1_000_000)).await;
	let bark2 = ctx.new_bark("bark2", &srv).await;

	bark1.board_and_confirm_and_register(&ctx, sat(800_000)).await;
	let [input_vtxo] = bark1.vtxos().await.try_into().expect("should have one vtxo");

	let send_amount = sat(300_000);
	let addr = bark2.get_onchain_address().await;
	bark1.send_onchain(&addr, send_amount).await;
	ctx.generate_blocks(2).await;

	let movements = bark1.history().await;
	let send_mvt = movements.last().unwrap();
	let fee = send_mvt.offchain_fee;

	// Fee includes base_fee (3,000) plus weight fee
	assert_eq!(fee, sat(3_938), "fee should be at least base_fee, got {}", fee);

	// Destination should receive exactly the requested amount
	assert_eq!(
		send_mvt.sent_to.first(),
		Some(MovementDestination {
			destination: PaymentMethod::Bitcoin(addr.to_string()),
			amount: send_amount,
		}).as_ref(),
	);

	// Change VTXO should be board_amount - send_amount - fee
	let [change_vtxo] = bark1.vtxos().await.try_into().expect("should have one vtxo");
	assert_eq!(change_vtxo.amount, input_vtxo.amount - send_amount - fee);

	// Verify on-chain receipt
	ctx.generate_blocks(1).await;
	assert_eq!(bark2.onchain_balance().await, send_amount);
}

#[tokio::test]
async fn lightning_receive_fee_deducted() {
	let ctx = TestContext::new("fees/lightning_receive_fee_deducted").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		cfg.fees.lightning_receive = LightningReceiveFees {
			base_fee: sat(500),
			ppm: PpmFeeRate::ONE_PERCENT,
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = Arc::new(ctx.new_bark_with_funds("bark", &srv, btc(3)).await);
	let board_amount = btc(2);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	// Create a lightning invoice and receive payment
	let pay_amount = sat(1_000_000);
	let invoice_info = bark.bolt11_invoice(pay_amount).await;

	let cloned_invoice_info = invoice_info.clone();
	let res = tokio::spawn(async move {
		lightning.sender.pay_bolt11(cloned_invoice_info.invoice).await
	});

	srv.wait_for_vtxopool(&ctx).await;
	bark.lightning_receive(&invoice_info.invoice).wait_millis(10_000).await;
	res.ready().await.unwrap();

	// Fee = base(500) + 1,000,000 * 10,000 / 1,000,000 = 500 + 10,000 = 10,500
	let expected_fee = sat(10_500);

	// Verify balance: board amount + (pay_amount - fee)
	assert_eq!(bark.spendable_balance().await, board_amount + pay_amount - expected_fee);

	// Verify movement
	let movements = bark.history().await;
	assert_eq!(movements.len(), 2); // board + lightning receive
	let ln_mvt = movements.last().unwrap();
	assert_eq!(ln_mvt.subsystem.name, "bark.lightning_receive");
	assert_eq!(ln_mvt.offchain_fee, expected_fee);
	assert_eq!(ln_mvt.intended_balance, pay_amount.to_signed().unwrap());
	assert_eq!(ln_mvt.effective_balance, (pay_amount - expected_fee).to_signed().unwrap());
}

#[tokio::test]
async fn lightning_receive_fee_rejects_when_fee_exceeds_amount() {
	let ctx = TestContext::new("fees/lightning_receive_fee_rejects_when_fee_exceeds_amount").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.receiver), |cfg| {
		// Set a very high base_fee so that small amounts are rejected
		cfg.fees.lightning_receive = LightningReceiveFees {
			base_fee: sat(50_000),
			ppm: PpmFeeRate::ZERO,
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, btc(3)).await;
	bark.board_and_confirm_and_register(&ctx, btc(2)).await;

	// Try to create an invoice for 50,000 sats when fee is 50,000
	let err = bark.try_bolt11_invoice(sat(50_000)).await.unwrap_err();
	assert!(
		err.to_alt_string().contains("exceeds amount"),
		"Expected fee exceeds amount error, got: {:#}", err,
	);
}

#[tokio::test]
async fn lightning_send_fee_deducted() {
	let ctx = TestContext::new("fees/lightning_send_fee_deducted").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.sender), |cfg| {
		cfg.fees.lightning_send = LightningSendFees {
			min_fee: Amount::ZERO,
			base_fee: sat(5_000),
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, btc(7)).await;
	let board_amount = btc(5);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	// Pay 2 BTC via lightning with a 5,000 sat base_fee (no ppm)
	let pay_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(pay_amount), "test_fee_payment", "fee test").await;
	bark.pay_lightning_wait(invoice, None).await;

	// Fee = base(5,000) + ppm(0) = 5,000
	let expected_fee = sat(5_000);

	// Balance should be: board(5 BTC) - payment(2 BTC) - fee(5,000 sats)
	assert_eq!(bark.spendable_balance().await, board_amount - pay_amount - expected_fee);

	// Verify movement
	let movements = bark.history().await;
	let send_mvt = movements.last().unwrap();
	assert_eq!(send_mvt.offchain_fee, expected_fee,
		"lightning_send_fee_deducted: offchain_fee mismatch");
	assert_eq!(send_mvt.intended_balance, -pay_amount.to_signed().unwrap(),
		"lightning_send_fee_deducted: intended_balance mismatch");
}

#[tokio::test]
async fn lightning_send_fee_min_fee_applies() {
	let ctx = TestContext::new("fees/lightning_send_fee_min_fee_applies").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.sender), |cfg| {
		cfg.fees.lightning_send = LightningSendFees {
			min_fee: sat(10_000),
			base_fee: sat(100),
			ppm_expiry_table: vec![],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, btc(7)).await;
	let board_amount = btc(5);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	// Pay 1 BTC via lightning: base(100) + ppm(0) = 100, but min_fee = 10,000
	let pay_amount = btc(1);
	let invoice = lightning.receiver.invoice(Some(pay_amount), "test_min_fee", "min fee test").await;
	bark.pay_lightning_wait(invoice, None).await;

	// Fee = max(10,000, 100 + 0) = 10,000
	let expected_fee = sat(10_000);

	assert_eq!(bark.spendable_balance().await, board_amount - pay_amount - expected_fee);

	// Verify movement
	let movements = bark.history().await;
	let send_mvt = movements.last().unwrap();
	assert_eq!(send_mvt.offchain_fee, expected_fee,
		"lightning_send_fee_min_fee_applies: offchain_fee mismatch");
	assert_eq!(send_mvt.intended_balance, -pay_amount.to_signed().unwrap(),
		"lightning_send_fee_min_fee_applies: intended_balance mismatch");
}

#[tokio::test]
async fn lightning_send_fee_ppm_expiry_table() {
	let ctx = TestContext::new("fees/lightning_send_fee_ppm_expiry_table").await;

	let lightning = ctx.new_lightning_setup("lightningd").await;

	let srv = ctx.new_captaind_with_cfg("server", Some(&lightning.sender), |cfg| {
		cfg.vtxo_lifetime = 144;
		cfg.fees.lightning_send = LightningSendFees {
			min_fee: Amount::ZERO,
			base_fee: sat(1_000),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO },
				PpmExpiryFeeEntry { expiry_blocks_threshold: 50, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(10)).await;

	let bark = ctx.new_bark_with_funds("bark", &srv, btc(7)).await;
	let board_amount = btc(5);
	bark.board_and_confirm_and_register(&ctx, board_amount).await;

	lightning.sync().await;

	// Pay 2 BTC via lightning. VTXO has ~130+ blocks until expiry, exceeding the
	// 50-block threshold, so 1% ppm applies.
	// Fee = base(1,000) + ppm_expiry(2 BTC × 1%) = 1,000 + 2,000,000 = 2,001,000
	let pay_amount = btc(2);
	let invoice = lightning.receiver.invoice(Some(pay_amount), "test_ppm_expiry", "ppm expiry test").await;
	bark.pay_lightning_wait(invoice, None).await;

	let expected_fee = sat(2_001_000);

	// Balance should be: board(5 BTC) - payment(2 BTC) - fee(2,001,000 sats)
	assert_eq!(bark.spendable_balance().await, board_amount - pay_amount - expected_fee);

	// Verify movement
	let movements = bark.history().await;
	let send_mvt = movements.last().unwrap();
	assert_eq!(send_mvt.offchain_fee, expected_fee);
	assert_eq!(send_mvt.intended_balance, -pay_amount.to_signed().unwrap());
	assert_eq!(send_mvt.effective_balance, -(pay_amount + expected_fee).to_signed().unwrap());
}
