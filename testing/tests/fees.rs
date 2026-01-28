use bdk_esplora::esplora_client::Amount;
use bitcoin::FeeRate;

use ark::fees::{BoardFees, PpmFeeRate};
use bitcoin_ext::FeeRateExt;

use ark_testing::{btc, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::exit::complete_exit;

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