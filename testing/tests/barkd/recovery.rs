
use std::time::Duration;

use ark_testing::{btc, sat, TestContext};
use bitcoin::Amount;

use super::helpers::{wait_for_rounds_complete, wait_for_spendable_vtxos};

/// Wallet recovery from seed.
///
/// Board and register a VTXO, then wipe the daemon's datadir down to nothing
/// but the seed and recover in place. Asserts the recovered wallet rediscovers
/// the very same VTXO.
#[tokio::test]
async fn recovered_wallet_finds_boarded_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_boarded_vtxo").await;

	let srv = ctx.captaind("server").create().await;

	// Board and register a single VTXO with the Ark server.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 1, "wallet should have one boarded VTXO before recovery");

	let mnemonic = barkd.mnemonic().await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	// Drive whatever sync/recovery the wallet exposes.
	recovered.onchain_sync().await;
	recovered.sync().await;

	// The recovered wallet must rediscover the same VTXO.
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(), "recovered wallet should rediscover the same number of VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id), "recovered wallet should rediscover the VTXO with id {:?}", vtxo.vtxo.id);
	}

	// Spend recovered VTXOs in a payment (board minus fees)
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(99_443)).await;
}

/// Wallet recovery from seed after a round refresh.
///
/// Board a VTXO, then refresh it into a round: the board VTXO is spent as the
/// round input and a fresh round-output VTXO is produced. After recovering from
/// the same seed, only the round output should be recovered — the board VTXO
/// was spent in the round, so the server reports it spent and recovery skips it.
#[tokio::test]
async fn recovered_wallet_finds_round_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_round_vtxo").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Board a VTXO.
	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;

	let board = barkd.vtxos(None).await;
	assert_eq!(board.len(), 1, "should have one boarded VTXO");
	let board_id = board[0].vtxo.id;

	// Refresh it into a round and confirm the round. The default round interval
	// is long, so the round needs an explicit trigger alongside the refresh.
	tokio::join!(barkd.refresh_all(), srv.trigger_round());
	wait_for_rounds_complete(&ctx, &barkd).await;

	let after_refresh = barkd.vtxos(None).await;
	assert_eq!(after_refresh.len(), 1, "should hold one round-output VTXO after refresh");
	let round_id = after_refresh[0].vtxo.id;
	assert_ne!(round_id, board_id, "refresh should produce a new VTXO id");

	// Recover from the same seed into a fresh wallet.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;

	recovered.onchain_sync().await;
	recovered.sync().await;

	// Only the round output is recovered; the board VTXO is spent (round input).
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "recovered wallet should hold exactly one VTXO");
	assert_eq!(after[0].vtxo.id, round_id, "recovered VTXO should be the round output");

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(99_443)).await;
}

/// Wallet recovery from seed across a long arkoor chain.
///
/// Each arkoor send spends the wallet's current change and produces a new
/// change, so a run of sends builds a deep genesis chain and accumulates many
/// change VTXO ids in the recovery mailbox — all but the last spent into the
/// next. Recovery must rebuild only the single unspent leaf and skip every
/// spent intermediate change (recognised as an ancestor of the leaf), rather
/// than resurrecting them.
#[tokio::test]
async fn recovered_wallet_finds_arkoor_receive_and_change_vtxos() {
	let ctx = TestContext::new("barkd/recovered_wallet_handles_long_arkoor_chain").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Sender boards a large VTXO; recipient just supplies an address to send to.
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let dest = recipient.ark_address().await;

	// Send multiple arkoors
	const CHAIN_LEN: usize = 8;
	for _ in 0..CHAIN_LEN {
		sender.send(&dest, sat(1_000)).await;
	}

	let sender_before = sender.vtxos(None).await;
	assert_eq!(sender_before.len(), 1,
		"sender should hold a single change VTXO at the chain tip");

	// Recover from the same seed into a fresh wallet.
	let sender_mnemonic = sender.mnemonic().await;
	let sender_recovered = ctx.barkd("sender_recovered", &srv)
		.mnemonic(sender_mnemonic)
		.create().await;

	sender_recovered.onchain_sync().await;
	sender_recovered.sync().await;

	// Exactly the unspent chain tip is recovered — the spent intermediate
	// changes must not be resurrected.
	let sender_after = sender_recovered.vtxos(Some(true)).await;
	assert_eq!(sender_after.len(), 1,
		"recovered sender wallet should hold exactly the chain-tip VTXO");
	assert_eq!(sender_after[0].vtxo.id, sender_before[0].vtxo.id,
		"recovered VTXO should be the chain tip");

	let recipient_before = recipient.vtxos(None).await;
	assert_eq!(recipient_before.len(), 8, "recipient should hold 8 arkoor receive VTXOs");

	let recipient_mnemonic = recipient.mnemonic().await;
	let recipient_recovered = ctx.barkd("recipient_recovered", &srv)
		.mnemonic(recipient_mnemonic)
		.create().await;

	// Drive whatever sync/recovery the wallet exposes.
	recipient_recovered.onchain_sync().await;
	recipient_recovered.sync().await;

	// The recovered wallet must rediscover the same VTXO.
	let recipient_after = recipient_recovered.vtxos(Some(true)).await;
	assert_eq!(recipient_after.len(), recipient_before.len(),
		"recovered recipient wallet should rediscover the same number of VTXOs");
	for vtxo in recipient_before.iter() {
		assert!(
			recipient_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered recipient wallet should rediscover the VTXO with id {:?}",
			vtxo.vtxo.id
		);
	}

	// Spend recovered VTXOs in a payment
	sender_recovered.send(&recipient.ark_address().await, Amount::from_sat(991_443)).await;
	recipient_recovered.send(&sender.ark_address().await, Amount::from_sat(8_000)).await;
}

/// Wallet recovery of a claimed Lightning-receive output.
///
/// Receive a Lightning payment and claim it (producing a spendable VTXO), then
/// recover from the same seed and assert the recovered wallet rediscovers the
/// claimed receive output. Runs on both the external-lightningd and intra-ark
/// topologies via the `lightning_test!` harness.
#[tokio::test]
async fn recovered_wallet_finds_lightning_receive() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_receive").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;

	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).create().await;

	let amount = sat(500_000);
	let invoice = barkd.lightning_invoice(amount).await;

	// Pay the invoice and wait for the wallet to claim the receive into a
	// spendable VTXO.
	tokio::join!(
		lightning.external.pay_bolt11(invoice.invoice),
		async {
			let mut claimed = false;
			for _ in 0..30 {
				tokio::time::sleep(Duration::from_millis(500)).await;
				barkd.sync().await;
				if barkd.bark_balance().await.spendable == amount {
					claimed = true;
					break;
				}
			}
			assert!(claimed, "lightning receive should be claimed");
		},
	);

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 1, "should hold one lightning-receive VTXO after claim");
	let recv_id = before[0].vtxo.id;

	// Recover from the same seed into a fresh wallet.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "recovered wallet should hold the lightning-receive VTXO");
	assert_eq!(after[0].vtxo.id, recv_id, "recovered VTXO should be the claimed receive output");

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(500_000)).await;
}

/// Wallet recovery of a Lightning-send change output.
///
/// Pay a Lightning invoice (a successful send): the wallet's VTXO is spent and
/// a change VTXO comes back. After recovering from the seed, the change must be
/// rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_lightning_send_change() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_send_change").await;
	let lightning = ctx.new_lightning_setup("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).boarded(sat(1_000_000)).create().await;
	let board = barkd.vtxos(None).await;
	let board_id = board[0].vtxo.id;

	// Pay a 300k invoice: the send succeeds, spending the board VTXO and
	// leaving a change VTXO.
	let invoice = lightning.external.invoice(Some(sat(300_000)), "send", "send").await;
	lightning.sync().await;
	barkd.pay_lightning(&invoice).await;

	// The REST send returns before the payment resolves, so drive it via sync
	// until the change VTXO has replaced the board VTXO.
	let mut before = None;
	for _ in 0..30 {
		tokio::time::sleep(Duration::from_millis(500)).await;
		barkd.sync().await;
		let vtxos = barkd.vtxos(None).await;
		if vtxos.len() == 1 && vtxos[0].vtxo.id != board_id {
			before = Some(vtxos);
			break;
		}
	}
	let before = before.expect("lightning send should resolve to a single change VTXO");

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover both the change and revocation VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(699_443)).await;
}

/// Wallet recovery of Lightning-send change and revocation outputs.
///
/// With no channel, a Lightning send can't be routed: the payment fails and the
/// wallet recovers its funds as a revocation VTXO alongside the change VTXO.
/// After recovering from the seed, both must be rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_lightning_send_revocation() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_lightning_send_revocation").await;
	let lightning = ctx.new_lightning_setup_no_channel("lightningd").await;
	let srv = ctx.captaind("server")
		.lightningd(&lightning.internal)
		.funded(btc(10))
		.create().await;
	srv.wait_for_vtxopool(&ctx).await;
	ctx.generate_blocks(1).await;

	let barkd = ctx.barkd("barkd", &srv).boarded(sat(1_000_000)).create().await;

	// Pay a 300k invoice with no route: the send fails and the wallet ends up
	// with two VTXOs — the change and the revoked payment amount.
	let invoice = lightning.external.invoice(Some(sat(300_000)), "send", "send").await;
	lightning.sync().await;
	barkd.pay_lightning(&invoice).await;

	// Drive the failed send to its revocation via sync.
	let mut before = None;
	for _ in 0..30 {
		tokio::time::sleep(Duration::from_millis(500)).await;
		barkd.sync().await;
		let vtxos = barkd.vtxos(None).await;
		if vtxos.len() == 2 {
			before = Some(vtxos);
			break;
		}
	}
	let before = before.expect("failed lightning send should produce change + revocation VTXOs");

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover both the change and revocation VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(999_443)).await;
}

/// Wallet recovery of an offboard (send-onchain) change output.
///
/// Send part of a VTXO on-chain (an offboard), leaving the remainder as an
/// off-chain change VTXO, then recover from the seed and assert the change is
/// rediscovered. The offboard mints the change via a checkpointed arkoor, so
/// this exercises arkoor-change recovery.
#[tokio::test]
async fn recovered_wallet_finds_offboard_change() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_offboard_change").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let addr = recipient.onchain_address().await;

	let board = barkd.vtxos(None).await;
	let board_id = board[0].vtxo.id;

	// Offboard 300k on-chain; the remainder comes back as a change VTXO.
	barkd.send_onchain(&addr.to_string(), sat(300_000)).await;
	ctx.generate_blocks(2).await;

	// Wait for the change to settle spendable so we don't capture a transient
	// locked intermediate the server already considers spent.
	let before = wait_for_spendable_vtxos(&barkd, 1).await;
	let change_id = before[0].vtxo.id;
	assert_ne!(change_id, board_id, "offboard should produce a new change VTXO");

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "recovered wallet should hold the offboard change VTXO");
	assert_eq!(after[0].vtxo.id, change_id, "recovered VTXO should be the offboard change");

	// Spend recovered VTXOs in a payment
	recovered.send(&recipient.ark_address().await, Amount::from_sat(698_505)).await;
}
