use ark::{ProtocolEncoding, Vtxo, VtxoId};
use ark::vtxo::Full;
use ark_testing::{btc, require_bark_version, sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;
use ark_testing::daemon::captaind::{self, ArkClient, MailboxClient};
use bark_json::primitives::VtxoStateInfo;
use bitcoin::Amount;
use server_rpc::protos;

use crate::helpers::wait_for_boards_synced;

use super::helpers::{
	wait_for_exits_claimable, wait_for_rounds_complete, wait_for_spendable,
	wait_for_spendable_vtxos, wait_for_vtxos,
};

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
	let ctx = TestContext::new("barkd/recovered_wallet_finds_arkoor_receive_and_change_vtxos").await;

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
		wait_for_spendable(&barkd, amount),
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
	// until the change VTXO has replaced the board VTXO. Require it spendable so
	// we don't capture the transient in-flight HTLC (locked, and spent once the
	// payment settles) that briefly is the only unspent VTXO.
	let before = wait_for_vtxos(&barkd, |vtxos| {
		vtxos.len() == 1 && vtxos[0].vtxo.id != board_id
			&& vtxos[0].state == VtxoStateInfo::Spendable
	}).await;

	// Recover from the same seed.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("barkd_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover the change VTXO");
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

	// Wait for both VTXOs to settle spendable: this skips the transient
	// {change, locked-htlc} state and captures the settled {change, revocation}
	// set, since the HTLC is spent into the revocation VTXO under a new id.
	let before = wait_for_spendable_vtxos(&barkd, 2).await;

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

/// Recovery yields nothing for a fully-spent wallet.
///
/// Offboard everything on-chain (no change remains), then recover from the
/// seed: the spent board VTXO must not be resurrected.
#[tokio::test]
async fn recovered_wallet_is_empty_when_fully_spent() {
	let ctx = TestContext::new("barkd/recovered_wallet_is_empty_when_fully_spent").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(500_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;
	let addr = recipient.onchain_address().await;

	// Offboard everything on-chain — no change VTXO remains.
	barkd.offboard_all(&addr.to_string()).await;
	ctx.generate_blocks(2).await;
	barkd.sync().await;
	assert!(barkd.vtxos(None).await.is_empty(),
		"wallet should hold no VTXOs after offboarding everything");

	// Recover from the same seed: there is nothing to recover.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert!(after.is_empty(), "recovered wallet should hold no VTXOs, got {:?}", after);
}

/// Recovery does not resurrect a unilaterally-exited VTXO.
///
/// Board a VTXO, exit it on-chain, then recover from the seed: the exited VTXO
/// must not come back as a spendable off-chain VTXO.
#[tokio::test]
async fn recovered_wallet_skips_exited_vtxo() {
	// The daemon's background exit auto-progress (run_exits) is required to
	// drive the CPFP broadcast to completion.
	require_bark_version!(> "0.2.0");

	let ctx = TestContext::new("barkd/recovered_wallet_skips_exited_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let barkd = ctx.barkd("bark", &srv).boarded(sat(500_000)).create().await;

	let [before] = barkd.vtxos(Some(true)).await.try_into().expect("should hold one VTXO");

	// Unilaterally exit the board VTXO on-chain. The on-chain wallet is empty
	// after boarding, so fund it to pay the exit CPFP fees.
	barkd.exit_start_all().await;
	ctx.fund_barkd(&barkd, sat(100_000)).await;
	wait_for_exits_claimable(&ctx, &barkd).await;
	barkd.sync().await;
	assert!(barkd.vtxos(None).await.is_empty(),
		"exited VTXO should no longer be a spendable VTXO");

	// Recover from the same seed: the exited VTXO must not be resurrected.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let [after] = recovered.vtxos(Some(true)).await.try_into().expect("should hold one VTXO");
	assert_eq!(after.vtxo.id, before.vtxo.id);
	assert_eq!(after.state, VtxoStateInfo::Exited,
		"recovered wallet should mark the exited VTXO as such");
}

/// Recovery of a wallet holding VTXOs of multiple origins at once.
///
/// Build a wallet that simultaneously holds a board VTXO, a round-output VTXO
/// (from refreshing a second board), and an arkoor-receive VTXO, then recover
/// from the seed and assert all three are rediscovered.
#[tokio::test]
async fn recovered_wallet_finds_mixed_origin_vtxos() {
	let ctx = TestContext::new("barkd/recovered_wallet_finds_mixed_origin_vtxos").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Board VTXO #1 — kept as the board leaf. Fund extra on-chain so a second
	// board has coins to spend (boarding consumes the whole on-chain balance).
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(300_000))
		.funded(sat(400_000))
		.create().await;
	let board_id = barkd.vtxos(None).await[0].vtxo.id;

	// Board VTXO #2 and refresh just it into a round output.
	barkd.onchain_sync().await;
	let board_info = barkd.board_amount(sat(300_000)).await;
	ctx.await_transaction(board_info.funding_tx.txid).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;
	let second_board = barkd.vtxos(None).await
		.into_iter().find(|v| v.vtxo.id != board_id && v.state == VtxoStateInfo::Spendable)
		.expect("second board VTXO").vtxo.id;
	tokio::join!(
		barkd.refresh_vtxos(vec![second_board.to_string()]),
		srv.trigger_round(),
	);
	wait_for_rounds_complete(&ctx, &barkd).await;

	// Receive an arkoor payment from another wallet.
	let sender = ctx.barkd("sender", &srv).boarded(sat(500_000)).create().await;
	sender.send(&barkd.ark_address().await, sat(50_000)).await;
	barkd.sync().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 3,
		"wallet should hold board + round-output + arkoor-receive VTXOs, got {:?}", before);

	// Recover from the same seed and rediscover all three.
	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), before.len(),
		"recovered wallet should rediscover all VTXOs");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}

	// Spend recovered VTXOs in a payment
	let recipient = ctx.barkd("recipient", &srv).create().await;
	recovered.send(&recipient.ark_address().await, Amount::from_sat(649_443)).await;
}

/// Recovery tolerates a valid VTXO it cannot own.
///
/// Anyone who knows the mailbox id can post a valid, server-fetchable VTXO we
/// don't own. Recovery must skip it gracefully — not hang on the key search, not
/// abort wallet creation — and still recover the VTXOs we *do* own.
#[tokio::test]
async fn recovered_wallet_skips_unownable_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_skips_unownable_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// A foreign wallet boards a VTXO: it's valid and fetchable from the server,
	// but its owner key belongs to the foreign seed, not ours.
	let foreign = ctx.barkd("foreign", &srv).boarded(sat(100_000)).create().await;
	let foreign_id = foreign.vtxos(None).await[0].vtxo.id;

	// Our wallet boards its own VTXO, which is posted to our recovery mailbox.
	let victim = ctx.barkd("victim", &srv).boarded(sat(100_000)).create().await;
	let own_id = victim.vtxos(None).await[0].vtxo.id;
	let mnemonic = victim.mnemonic().await;

	// Proxy the server and inject the foreign id into every recovery-mailbox
	// read, so the recovering wallet is handed a VTXO it can never own. The
	// genuine messages (our own posted ids) are passed through untouched.
	#[derive(Clone)]
	struct InjectForeignId { foreign_id: VtxoId }

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InjectForeignId {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, MailboxMessage, RecoveryVtxoIdsMessage};

			let mut resp = upstream.read_mailbox(req).await?.into_inner();
			resp.messages.push(MailboxMessage {
				message: Some(mailbox_message::Message::RecoveryVtxoIds(RecoveryVtxoIdsMessage {
					vtxo_ids: vec![self.foreign_id.to_bytes().to_vec()],
				})),
				checkpoint: 0,
			});
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox((), InjectForeignId { foreign_id }).await;

	// Recover from our seed, talking to the server through the injecting proxy.
	let recovered = ctx.barkd("victim_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	// Wallet creation returned (recovery did not hang or abort) and we recovered
	// exactly our own VTXO; the unownable foreign one was skipped.
	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1,
		"recovered wallet should hold only its own VTXO, got {:?}", after);
	assert_eq!(after[0].vtxo.id, own_id, "recovered VTXO should be our own board");
	assert!(!after.iter().any(|v| v.vtxo.id == foreign_id),
		"unownable foreign VTXO must not be recovered");
}

/// Recovery skips a VTXO that fails validation.
///
/// A buggy or malicious server could return a VTXO whose owner key we can derive
/// but whose signatures are invalid. Recovery must validate and skip it rather
/// than import unspendable junk.
#[tokio::test]
async fn recovered_wallet_skips_invalid_vtxo() {
	let ctx = TestContext::new("barkd/recovered_wallet_skips_invalid_vtxo").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;
	let mnemonic = barkd.mnemonic().await;

	// Proxy get_vtxo to return our own board VTXO with an invalidated signature.
	#[derive(Clone)]
	struct ForgeVtxo;

	#[async_trait::async_trait]
	impl captaind::proxy::ArkRpcProxy for ForgeVtxo {
		async fn get_vtxo(
			&self, upstream: &mut ArkClient, req: protos::GetVtxoRequest,
		) -> Result<protos::GetVtxoResponse, tonic::Status> {
			let mut resp = upstream.get_vtxo(req).await?.into_inner();
			let mut vtxo = Vtxo::<Full>::deserialize(&resp.vtxo).unwrap();
			vtxo.invalidate_final_sig();
			resp.vtxo = vtxo.serialize();
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox(ForgeVtxo, ()).await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	assert!(recovered.vtxos(Some(true)).await.is_empty(),
		"recovery must skip a VTXO that fails validation");
}

/// Recovery tolerates an undecodable id in the recovery mailbox.
///
/// A corrupt or malformed mailbox entry must be skipped without derailing the
/// rest of the scan.
#[tokio::test]
async fn recovered_wallet_tolerates_undecodable_vtxo_id() {
	let ctx = TestContext::new("barkd/recovered_wallet_tolerates_undecodable_vtxo_id").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let barkd = ctx.barkd("bark", &srv).boarded(sat(100_000)).create().await;
	let own_id = barkd.vtxos(None).await[0].vtxo.id;
	let mnemonic = barkd.mnemonic().await;

	// Inject a garbage (undecodable) vtxo id alongside the genuine ones.
	#[derive(Clone)]
	struct InjectGarbageId;

	#[async_trait::async_trait]
	impl captaind::proxy::MailboxRpcProxy for InjectGarbageId {
		async fn read_mailbox(
			&self, upstream: &mut MailboxClient, req: protos::mailbox_server::MailboxRequest,
		) -> Result<protos::mailbox_server::MailboxMessages, tonic::Status> {
			use protos::mailbox_server::{mailbox_message, MailboxMessage, RecoveryVtxoIdsMessage};

			let mut resp = upstream.read_mailbox(req).await?.into_inner();
			resp.messages.push(MailboxMessage {
				message: Some(mailbox_message::Message::RecoveryVtxoIds(RecoveryVtxoIdsMessage {
					vtxo_ids: vec![vec![0xde, 0xad, 0xbe, 0xef]],
				})),
				checkpoint: 0,
			});
			Ok(resp)
		}
	}

	let proxy = srv.start_proxy_with_mailbox((), InjectGarbageId).await;

	let recovered = ctx.barkd("bark_recovered", &srv)
		.mnemonic(mnemonic)
		.cfg({
			let addr = proxy.address.clone();
			move |c| c.server_address = addr
		})
		.create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 1, "the valid VTXO must still recover despite a garbage id");
	assert_eq!(after[0].vtxo.id, own_id, "recovered VTXO should be the board");
}

/// Recovery reads a recovery mailbox that spans multiple pages.
///
/// With the server's page size forced to 1, two boarded VTXOs land on separate
/// mailbox pages, exercising the `have_more` pagination loop.
#[tokio::test]
async fn recovered_wallet_reads_paginated_mailbox() {
	let ctx = TestContext::new("barkd/recovered_wallet_reads_paginated_mailbox").await;
	let srv = ctx.captaind("server")
		.cfg(|c| c.max_read_mailbox_items = 1)
		.funded(btc(10))
		.create().await;

	// Board twice so the recovery mailbox holds two ids (two pages at size 1).
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(100_000))
		.funded(sat(200_000))
		.create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.wait_for_boards_synced().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 2, "wallet should hold two board VTXOs");

	let mnemonic = barkd.mnemonic().await;
	let recovered = ctx.barkd("bark_recovered", &srv).mnemonic(mnemonic).create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	let after = recovered.vtxos(Some(true)).await;
	assert_eq!(after.len(), 2, "both VTXOs must recover across mailbox pages");
	for vtxo in before.iter() {
		assert!(after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"recovered wallet should rediscover VTXO {:?}", vtxo.vtxo.id);
	}
}

/// Recovery does not recover a VTXO whose key is beyond the gap limit.
///
/// The recipient advances its key index well past `STOP_GAP` (50) by minting
/// many addresses, then receives into the last one. A freshly recovered wallet
/// only scans `STOP_GAP` keys ahead of the last match, so this VTXO is out of
/// reach and — by design — is not recovered.
#[tokio::test]
async fn recovered_wallet_skips_vtxo_beyond_gap_limit() {
	let ctx = TestContext::new("barkd/recovered_wallet_skips_vtxo_beyond_gap_limit").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).create().await;

	// Mint 60 addresses (> STOP_GAP of 50), each revealing a fresh key, then
	// receive into the last (highest-index) one.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(50_000)).await;
	recipient.sync().await;
	assert_eq!(recipient.vtxos(None).await.len(), 1, "recipient should hold the received VTXO");

	let mnemonic = recipient.mnemonic().await;
	let recovered = ctx.barkd("recipient_recovered", &srv).mnemonic(mnemonic).create().await;
	recovered.onchain_sync().await;
	recovered.sync().await;

	assert!(recovered.vtxos(Some(true)).await.is_empty(),
		"a VTXO beyond the gap limit must not be recovered");
}

/// Recovery from the same seed is repeatable.
///
/// Recovery must be deterministic and leave no trace on the source wallet: two
/// independent fresh wallets recovered from the same seed must rediscover the
/// very same VTXO set. A second recovery that double-imported, ratcheted the key
/// index, or otherwise diverged from the first would show up here.
#[tokio::test]
async fn recovered_wallet_recovery_is_repeatable() {
	let ctx = TestContext::new("barkd/recovered_wallet_recovery_is_repeatable").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;

	// Hold two board VTXOs so a divergent re-scan has something to get wrong.
	let barkd = ctx.barkd("bark", &srv)
		.boarded(sat(100_000))
		.funded(sat(200_000))
		.create().await;
	barkd.onchain_sync().await;
	barkd.board_amount(sat(100_000)).await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	barkd.wait_for_boards_synced().await;

	let before = barkd.vtxos(None).await;
	assert_eq!(before.len(), 2, "wallet should hold two board VTXOs");
	let mnemonic = barkd.mnemonic().await;

	// Recover the same seed into two independent fresh wallets.
	let first = ctx.barkd("first_recovered", &srv).mnemonic(mnemonic.clone()).create().await;
	first.onchain_sync().await;
	first.sync().await;

	let second = ctx.barkd("second_recovered", &srv).mnemonic(mnemonic).create().await;
	second.onchain_sync().await;
	second.sync().await;

	let first_after = first.vtxos(Some(true)).await;
	let second_after = second.vtxos(Some(true)).await;
	assert_eq!(first_after.len(), before.len(), "first recovery should rediscover both VTXOs");
	assert_eq!(second_after.len(), first_after.len(),
		"a repeated recovery from the same seed must rediscover the same number of VTXOs");
	for vtxo in before.iter() {
		assert!(first_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"first recovery should rediscover VTXO {:?}", vtxo.vtxo.id);
		assert!(second_after.iter().any(|v| v.vtxo.id == vtxo.vtxo.id),
			"repeated recovery should rediscover VTXO {:?}", vtxo.vtxo.id);
	}
}
