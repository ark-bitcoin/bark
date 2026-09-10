use std::str::FromStr;

use tokio::fs;

use ark_testing::{sat, TestContext};

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
