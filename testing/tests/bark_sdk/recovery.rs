use std::collections::HashMap;
use std::str::FromStr;

use tokio::fs;

use bark::vtxo::VtxoState;
use server_rpc::protos;

use ark_testing::{sat, TestContext};
use ark_testing::daemon::captaind::{self, MailboxClient};

/// The gap limit must tolerate a run of unused key indices *between* matches,
/// not only before the first one.
///
/// Two VTXOs sit exactly `vtxo_key_gap_limit` unused indices apart, so the scan
/// matches the first and then has to cross the whole run to reach the second. A
/// window that stops at the end of that run instead of one past it leaves the
/// second VTXO behind.
#[tokio::test]
async fn recovery_finds_vtxos_separated_by_the_gap_limit() {
	const GAP: u32 = 2;

	let ctx = TestContext::new("bark_sdk/recovery_finds_vtxos_separated_by_the_gap_limit").await;
	let srv = ctx.captaind("server").create().await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &srv).create().await;

	// Receive into one key, reveal GAP more without receiving into them, then
	// receive into the key just past that run.
	let (first, first_idx) = target.new_address_with_index().await.expect("new address");
	for _ in 0..GAP {
		target.new_address().await.expect("new address");
	}
	let (second, second_idx) = target.new_address_with_index().await.expect("new address");
	assert_eq!(second_idx, first_idx + GAP + 1,
		"the two receiving keys must be exactly GAP unused indices apart",
	);

	source.send_arkoor_payment(&first, sat(10_000)).await.expect("arkoor send");
	source.send_arkoor_payment(&second, sat(20_000)).await.expect("arkoor send");
	target.sync().await;
	assert_eq!(target.spendable_vtxos().await.expect("list target vtxos").len(), 2,
		"target should hold both received vtxos",
	);

	// Recover from the same seed at that gap limit. Nothing but the scan can
	// find the second vtxo: the arkoor mailbox delivery is refused for a key
	// the wallet has not revealed.
	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.cfg(|c| c.vtxo_key_gap_limit = GAP)
		.create().await;

	let recovered_ids = recovered.spendable_vtxos().await.expect("list recovered vtxos")
		.iter().map(|v| v.id()).collect::<Vec<_>>();
	assert_eq!(recovered_ids.len(), 2,
		"both vtxos should be recovered, got {recovered_ids:?}",
	);
}

/// Acknowledges every post to the recovery mailbox without forwarding it, so the
/// recovery mailbox stays empty while the wallet believes its ids are backed up.
#[derive(Clone)]
struct SwallowRecoveryPosts;

#[async_trait::async_trait]
impl captaind::proxy::MailboxRpcProxy for SwallowRecoveryPosts {
	async fn post_recovery_vtxo_ids(
		&self,
		_upstream: &mut MailboxClient,
		_req: protos::mailbox_server::PostRecoveryVtxoIdsRequest,
	) -> Result<protos::core::Empty, tonic::Status> {
		Ok(protos::core::Empty {})
	}
}

/// A wallet recovered from its seed must not hold a vtxo it already spent.
///
/// The target's ids never reach the recovery mailbox, so the vtxo it receives is
/// only known to the regular mailbox. It spends that vtxo in full, and the
/// wallet recovered from the same seed must still show it as spent.
#[ignore = "known bug: the recovered wallet resurrects the spent vtxo as spendable"]
#[tokio::test]
async fn recovered_wallet_keeps_spent_vtxo_spent() {
	let ctx = TestContext::new("bark_sdk/recovered_wallet_keeps_spent_vtxo_spent").await;
	let srv = ctx.captaind("server").create().await;

	// The server acknowledges the recovery posts but stores nothing, so the
	// wallet has no way to notice its ids never got backed up.
	let proxy = srv.start_proxy_with_mailbox((), SwallowRecoveryPosts).await;

	let source = ctx.bark_sdk("source", &srv).boarded(sat(400_000)).create().await;
	let target = ctx.bark_sdk("target", &proxy).create().await;

	let target_address = target.new_address().await.expect("new address");
	source.send_arkoor_payment(&target_address, sat(100_000)).await.expect("arkoor send");
	target.sync().await;

	let received = target.spendable_vtxos().await.expect("list target vtxos");
	assert_eq!(received.len(), 1, "target should hold exactly the received vtxo");
	let vtxo_a = received[0].id();

	// Send the whole amount back, so the target keeps nothing.
	let back = source.new_address().await.expect("new address");
	target.send_arkoor_payment(&back, sat(100_000)).await.expect("arkoor send back");

	let mnemonic = fs::read_to_string(ctx.datadir.join("target/mnemonic")).await
		.expect("target mnemonic file");
	let mnemonic = bip39::Mnemonic::from_str(mnemonic.trim()).expect("parse mnemonic");
	drop(target);

	let recovered = ctx.bark_sdk("recovered", &srv)
		.mnemonic(mnemonic)
		.create().await;
	recovered.sync().await;

	let states = recovered.all_vtxos().await.expect("list recovered vtxos")
		.into_iter().map(|v| (v.id(), v.state)).collect::<HashMap<_, _>>();
	assert_eq!(states.get(&vtxo_a), Some(&VtxoState::Spent),
		"the spent vtxo must stay spent after recovery, got {states:?}",
	);
}
