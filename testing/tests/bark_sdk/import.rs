//! Manual VTXO import via [bark::Wallet::import_vtxo].

use ark_testing::{TestContext, sat};
use ark_testing::util::ToAltString;

use bark::ImportVtxoArgs;
use bark::vtxo::VtxoState;

/// A VTXO the server has already seen spent is imported as spent.
///
/// Ownership alone cannot tell a spent VTXO from a spendable one, so only the
/// server can. The spent record keeps it out of the balance and still leaves
/// the wallet an accurate history.
#[tokio::test]
async fn import_stores_spent_vtxo_as_spent() {
	let ctx = TestContext::new("bark_sdk/import_stores_spent_vtxo_as_spent").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [vtxo] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();
	let encoded = sender.get_full_vtxo(vtxo_id).await.expect("hydrate vtxo");

	// Spend it, so the server knows the VTXO is gone.
	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("send should succeed");

	// Drop the record, or the import stops at the row already in the db.
	// vtxos() does not list a spent vtxo, so drop it by id.
	sender.dangerous_drop_vtxo(vtxo_id).await.expect("drop the spent vtxo");

	sender.import_vtxo(&encoded, ImportVtxoArgs::default()).await
		.expect("importing a spent vtxo should record the spend");

	let imported = sender.get_vtxo_by_id(vtxo_id).await.expect("the spend should be recorded");
	assert_eq!(imported.state, VtxoState::Spent, "a spent vtxo must not come back as spendable");

	// vtxos() lists the unspent set, so the import must not have added to it.
	assert!(sender.vtxos().await.expect("list vtxos").iter().all(|v| v.vtxo.id() != vtxo_id),
		"a spent vtxo must stay out of the spendable set");
}

/// `skip_status_check` imports as spendable without asking the server.
///
/// The flag exists for callers that already know the state, so it must bypass
/// the query, even when that stores a spent VTXO as spendable.
#[tokio::test]
async fn import_can_skip_the_status_check() {
	let ctx = TestContext::new("bark_sdk/import_can_skip_the_status_check").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [vtxo] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();
	let encoded = sender.get_full_vtxo(vtxo_id).await.expect("hydrate vtxo");

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("send should succeed");
	sender.dangerous_drop_vtxo(vtxo_id).await.expect("drop the spent vtxo");

	let args = ImportVtxoArgs { skip_status_check: true, ..Default::default() };
	sender.import_vtxo(&encoded, args).await
		.expect("skipping the status check should import the spent vtxo as spendable");

	let imported = sender.get_vtxo_by_id(vtxo_id).await.expect("the vtxo should be stored");
	assert_eq!(imported.state, VtxoState::Spendable,
		"skipping the check means taking the caller's word for it");
}

/// An out-of-range gap limit is refused rather than attempted.
///
/// A scan for a key that is not ours crosses every index up to the limit and
/// derives a keypair for each, so `u32::MAX` would take hours and exhaust
/// memory. The limit arrives in a request body, so the ceiling must be enforced.
#[tokio::test]
async fn import_refuses_an_out_of_range_gap_limit() {
	let ctx = TestContext::new("bark_sdk/import_refuses_an_out_of_range_gap_limit").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [vtxo] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let encoded = sender.get_full_vtxo(vtxo.vtxo.id()).await.expect("hydrate vtxo");

	// A vtxo the receiver does not own, so nothing stops the scan early.
	let args = ImportVtxoArgs { gap_limit: Some(u32::MAX), ..Default::default() };
	let err = receiver.import_vtxo(&encoded, args).await
		.expect_err("an out-of-range gap limit must be refused");
	assert!(err.to_alt_string().contains("above the maximum"), "err: {err:#}");

	// The maximum itself is accepted, so the guard is a ceiling.
	let args = ImportVtxoArgs {
		gap_limit: Some(bark::MAX_VTXO_KEY_GAP_LIMIT),
		..Default::default()
	};
	let err = receiver.import_vtxo(&encoded, args).await
		.expect_err("the vtxo is still not the receiver's");
	assert!(err.to_alt_string().contains("unable to derive the key"), "err: {err:#}");
}
