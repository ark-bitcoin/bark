use bitcoin::Amount;

use ark::fees::{LightningSendFees, OffboardFees, PpmExpiryFeeEntry, PpmFeeRate};

use ark_testing::{btc, sat, TestContext};

#[tokio::test]
async fn estimate_lightning_send_fee_without_funds() {
	let ctx = TestContext::new("bark/estimate_lightning_send_fee_without_funds").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.lightning_send = LightningSendFees {
			min_fee: Amount::ZERO,
			base_fee: sat(1_000),
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO },
				PpmExpiryFeeEntry { expiry_blocks_threshold: u32::MAX, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark("bark1", &srv).await;

	// Without funds the fallback uses expiry_blocks=u32::MAX, which matches the u32::MAX
	// threshold so the 1% top tier applies. With real VTXOs this tier is unreachable.
	// Fee = base(1,000) + ppm_expiry(2 BTC × 1%) = 1,000 + 2,000,000 = 2,001,000
	let pay_amount = btc(2);
	let estimate = bark.estimate_lightning_send_fee(pay_amount).await;

	let expected_fee = sat(2_001_000);
	assert_eq!(estimate.fee, expected_fee);
	assert_eq!(estimate.net_amount, pay_amount);
	assert!(estimate.vtxos_spent.is_empty(), "no vtxos to select when wallet is empty");
}

#[tokio::test]
async fn estimate_send_onchain_fee_without_funds() {
	let ctx = TestContext::new("bark/estimate_send_onchain_fee_without_funds").await;
	let srv = ctx.new_captaind_with_cfg("server", None, |cfg| {
		cfg.fees.offboard = OffboardFees {
			base_fee: sat(1_000),
			fixed_additional_vb: 100,
			ppm_expiry_table: vec![
				PpmExpiryFeeEntry { expiry_blocks_threshold: 0, ppm: PpmFeeRate::ZERO },
				PpmExpiryFeeEntry { expiry_blocks_threshold: u32::MAX, ppm: PpmFeeRate::ONE_PERCENT },
			],
		};
	}).await;
	ctx.fund_captaind(&srv, btc(1)).await;

	let bark = ctx.new_bark("bark1", &srv).await;
	let address = ctx.bitcoind().get_new_address();

	// Without funds the fallback uses expiry_blocks=u32::MAX, which matches the u32::MAX
	// threshold so the 1% top tier applies. With real VTXOs this tier is unreachable.
	// Fee = base(1,000) + weight_fee(100 vb * feerate) + ppm_expiry(300,000 × 1% = 3,000)
	let send_amount = sat(300_000);
	let estimate = bark.estimate_send_onchain(&address, send_amount).await;

	// base_fee(1,000) + ppm(3,000) = 4,000, plus weight fee from fixed_additional_vb
	assert_eq!(estimate.fee, sat(4_854),
		"fee should include base_fee + top-tier ppm, got {}", estimate.fee);
	assert_eq!(estimate.net_amount, send_amount);
	assert!(estimate.vtxos_spent.is_empty(), "no vtxos to select when wallet is empty");
}
