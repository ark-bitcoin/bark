use tokio::fs;

use bark::BarkNetwork;

use ark_testing::{btc, sat, Bark, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::util::{get_bark_chain_source_from_env, TestContextChainSource};

#[ignore] // we removed this functionality, might be added again later
#[tokio::test]
async fn recover_mnemonic() {
	let ctx = TestContext::new("bark/recover_mnemonic").await;
	let srv = ctx.new_captaind_with_funds("server", None, btc(10)).await;
	let bark = ctx.new_bark_with_funds("bark", &srv, sat(2_000_000)).await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// make sure we have a round and an board vtxo (arkoor doesn't work)
	bark.refresh_all().await;
	bark.board(sat(800_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	let onchain = bark.onchain_balance().await;
	let _offchain = bark.spendable_balance().await;

	const MNEMONIC_FILE: &str = "mnemonic";
	let mnemonic = fs::read_to_string(bark.datadir().join(MNEMONIC_FILE)).await.unwrap();
	let _ = bip39::Mnemonic::parse(&mnemonic).expect("invalid mnemonic?");

	// first ensure we need to set a birthday for bitcoin core
	let bitcoind = if ctx.electrs.is_none() {
		Some(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await)
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_no_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_ref());
	let result = Bark::try_new_with_create_opts(
		"bark_recovered_no_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		None,
		true,
	).await;

	match get_bark_chain_source_from_env() {
		TestContextChainSource::BitcoinCore => {
			// it's not easy to get a grip of what the actual error was
			assert!(result.expect_err("--birthday-height should be required").to_string().contains(
				"You need to set the --birthday-height field when recovering from mnemonic.",
			));
		}
		_ => {
			let balance = result
				.expect("mnemonic should work without birthday")
				.onchain_balance()
				.await;
			assert_eq!(onchain, balance);
		}
	}

	// Now check that specifying a birthday height always succeeds
	let bitcoind = if ctx.electrs.is_none() {
		Some(ctx.new_bitcoind("bark_recovered_no_birthday_bitcoind").await)
	} else {
		None
	};
	let datadir = ctx.datadir.join("bark_recovered_with_birthday");
	let cfg = ctx.bark_default_cfg(&srv, bitcoind.as_ref());
	let recovered = Bark::try_new_with_create_opts(
		"bark_recovered_with_birthday",
		datadir,
		BarkNetwork::Regtest,
		cfg,
		bitcoind,
		Some(mnemonic.to_string()),
		Some(0),
		true,
	).await.expect("mnemonic + birthday should work");
	assert_eq!(onchain, recovered.onchain_balance().await);
	//TODO(stevenroose) implement offchain recovery
	// assert_eq!(offchain, recovered.offchain_balance().await);
}
