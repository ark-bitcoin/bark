
use ark_testing::{btc, sat, TestContext};
use ark_testing::util::ToAltString;
use bark_json::primitives::VtxoStateInfo;

/// Verify that `GET /wallet/vtxos/{id}` returns the VTXO detail.
#[tokio::test]
async fn get_vtxo_barkd() {
	let ctx = TestContext::new("barkd/get_vtxo_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(100_000)).create().await;

	let vtxos = barkd.vtxos(None).await;
	assert!(!vtxos.is_empty(), "should have at least one VTXO after boarding");

	let id = vtxos[0].vtxo.id.to_string();
	let detail = barkd.get_vtxo(&id).await;

	assert_eq!(detail.vtxo.id, vtxos[0].vtxo.id, "returned VTXO id should match");
	assert_eq!(detail.vtxo.amount, vtxos[0].vtxo.amount, "returned amount should match");
}

/// Verify that `GET /wallet/vtxos/{id}/encoded` returns the hex-encoded VTXO.
#[tokio::test]
async fn get_vtxo_encoded_barkd() {
	let ctx = TestContext::new("barkd/get_vtxo_encoded_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(100_000)).create().await;

	let vtxos = barkd.vtxos(None).await;
	assert!(!vtxos.is_empty(), "should have at least one VTXO after boarding");

	let id = vtxos[0].vtxo.id.to_string();
	let encoded = barkd.get_vtxo_encoded(&id).await;
	assert!(!encoded.encoded.0.is_empty(), "encoded field should not be empty");
}

/// Verify that `POST /wallet/import-vtxo` re-imports an exported VTXO.
#[tokio::test]
async fn import_vtxo_barkd() {
	let ctx = TestContext::new("barkd/import_vtxo_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).boarded(sat(100_000)).create().await;

	let vtxos = barkd.vtxos(None).await;
	assert!(!vtxos.is_empty(), "should have at least one VTXO after boarding");

	let id = vtxos[0].vtxo.id.to_string();
	let encoded = barkd.get_vtxo_encoded(&id).await;

	let imported = barkd.import_vtxo(barkd.import_vtxo_request(
		vec![encoded.encoded.0.clone()],
	)).await;
	assert_eq!(imported.len(), 1, "should return one imported VTXO");
	assert_eq!(imported[0].vtxo.id, vtxos[0].vtxo.id, "imported VTXO id should match");
}

/// `POST /wallet/import-vtxo` reaches a VTXO whose key is beyond the default
/// gap limit only when the request raises the limit.
///
/// The recipient advances its key index past the limit the recovering wallet is
/// pinned to, so that wallet does not know the user pubkey. The import must fail
/// at the wallet's limit and succeed once `gap_limit` crosses the run of unused
/// indices.
#[tokio::test]
async fn import_vtxo_gap_limit_barkd() {
	let ctx = TestContext::new("barkd/import_vtxo_gap_limit_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;

	// Derive 60 addresses, each revealing a fresh key, then receive into the last
	// one. The recovering wallet below is pinned to a limit that cannot reach it.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(50_000)).await;
	recipient.sync().await;

	let vtxos = recipient.vtxos(None).await;
	assert_eq!(vtxos.len(), 1, "recipient should hold the received VTXO");
	let encoded = recipient.get_vtxo_encoded(&vtxos[0].vtxo.id.to_string()).await;

	// A wallet recovered from the same seed cannot reach the key at a gap limit of
	// 50, so it starts empty.
	let recovered = ctx.barkd("recipient_recovered", &srv)
		.mnemonic(recipient.mnemonic().await)
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	recovered.onchain_sync().await;
	assert!(recovered.vtxos(None).await.is_empty(),
		"recovery must not reach the VTXO at a gap limit of 50");

	// A key the scan cannot reach is the request's own problem, so it must come
	// back as a 400 rather than a server error.
	let err = recovered
		.try_import_vtxo(recovered.import_vtxo_request(vec![encoded.encoded.0.clone()])).await
		.expect_err("import must fail while the user pubkey is beyond the gap limit");
	let err = err.to_alt_string();
	assert!(err.contains("status 400"), "unexpected import error: {err}");
	assert!(err.contains("unable to derive the key"), "unexpected import error: {err}");

	let mut req = recovered.import_vtxo_request(vec![encoded.encoded.0.clone()]);
	req.gap_limit = Some(100);
	let imported = recovered.import_vtxo(req).await;
	assert_eq!(imported.len(), 1, "a gap limit of 100 must reach the key at index 59");
	assert_eq!(imported[0].vtxo.id, vtxos[0].vtxo.id, "imported VTXO id should match");
}

/// `POST /wallet/import-vtxo` records the server's spend state, and
/// `skip_status_check` overrides it.
///
/// Recovery skips a vtxo the server has seen spent, so an import is the only
/// way to store it, and the flag decides which state it lands in. The two
/// wallets share a seed: an import is idempotent, so one wallet can only show
/// one outcome.
#[tokio::test]
async fn import_vtxo_skips_status_check_barkd() {
	let ctx = TestContext::new("barkd/import_vtxo_skips_status_check_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;

	// Receive past the limit the recovered wallets are pinned to, as in
	// import_vtxo_gap_limit_barkd, so they hold no row for the vtxo and the
	// imports below have to do the work.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(100_000)).await;
	recipient.sync().await;
	let vtxos = recipient.vtxos(None).await;
	assert_eq!(vtxos.len(), 1, "recipient should hold the received vtxo");
	let vtxo_id = vtxos[0].vtxo.id;
	let encoded = recipient.get_vtxo_encoded(&vtxo_id.to_string()).await.encoded.0;

	// Spend it onward, so the server records it as spent.
	recipient.send(&sender.ark_address().await, sat(50_000)).await;
	let mnemonic = recipient.mnemonic().await;

	let plain = ctx.barkd("recovered_plain", &srv)
		.mnemonic(mnemonic.clone())
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	plain.onchain_sync().await;
	assert!(plain.vtxos(Some(true)).await.is_empty(),
		"recovery must not reach the vtxo at a gap limit of 50");

	let mut req = plain.import_vtxo_request(vec![encoded.clone()]);
	req.gap_limit = Some(100);
	let imported = plain.import_vtxo(req).await;
	assert_eq!(imported.len(), 1, "the import should be accepted, not rejected");
	assert_eq!(imported[0].state, VtxoStateInfo::Spent,
		"the server reports it spent, so that is what should be recorded");

	let skipped = ctx.barkd("recovered_skipped", &srv)
		.mnemonic(mnemonic)
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	skipped.onchain_sync().await;
	assert!(skipped.vtxos(Some(true)).await.is_empty(),
		"same precondition: the skipped import must be the thing that stores it");

	let mut req = skipped.import_vtxo_request(vec![encoded]);
	req.gap_limit = Some(100);
	req.skip_status_check = true;
	let imported = skipped.import_vtxo(req).await;
	assert_eq!(imported.len(), 1, "the import should be accepted");
	assert_eq!(imported[0].state, VtxoStateInfo::Spendable,
		"skipping the check means taking the caller's word for it");
}

/// `allow_partial` decides whether one unimportable VTXO discards the rest.
///
/// The batch pairs a VTXO the recovering wallet owns with one belonging to a
/// stranger, so the second can never be imported. By default the whole request
/// is discarded and nothing is stored; with the flag set, the owned VTXO is
/// kept.
#[tokio::test]
async fn import_vtxo_partial_barkd() {
	let ctx = TestContext::new("barkd/import_vtxo_partial_barkd").await;

	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let sender = ctx.barkd("sender", &srv).boarded(sat(1_000_000)).create().await;
	let recipient = ctx.barkd("recipient", &srv).expose_mnemonic().create().await;
	let stranger = ctx.barkd("stranger", &srv).boarded(sat(1_000_000)).create().await;

	// Receive past the limit the recovering wallet is pinned to, so the import has
	// to do the work rather than short-circuiting on a stored row.
	let mut dest = String::new();
	for _ in 0..60 {
		dest = recipient.ark_address().await;
	}
	sender.send(&dest, sat(50_000)).await;
	recipient.sync().await;
	let mine = recipient.vtxos(None).await;
	assert_eq!(mine.len(), 1, "recipient should hold the received vtxo");
	let mine_id = mine[0].vtxo.id;
	let mine_hex = recipient.get_vtxo_encoded(&mine_id.to_string()).await.encoded.0;

	let theirs = stranger.vtxos(None).await;
	let theirs_hex = stranger.get_vtxo_encoded(&theirs[0].vtxo.id.to_string()).await.encoded.0;

	let recovered = ctx.barkd("recovered", &srv)
		.mnemonic(recipient.mnemonic().await)
		.cfg(|c| c.vtxo_key_gap_limit = 50)
		.create().await;
	recovered.onchain_sync().await;
	assert!(recovered.vtxos(Some(true)).await.is_empty(), "the recovered wallet starts empty");

	let batch = vec![mine_hex, theirs_hex];
	let mut req = recovered.import_vtxo_request(batch.clone());
	req.gap_limit = Some(100);
	let err = recovered.try_import_vtxo(req).await
		.expect_err("the default must refuse the whole batch");
	let err = err.to_alt_string();
	assert!(err.contains("status 400"), "unexpected import error: {err}");
	assert!(recovered.vtxos(Some(true)).await.is_empty(),
		"a refused batch must leave nothing stored");

	let mut req = recovered.import_vtxo_request(batch);
	req.gap_limit = Some(100);
	req.allow_partial = true;
	let imported = recovered.import_vtxo(req).await;
	assert_eq!(imported.len(), 1, "only the owned vtxo should land, got {imported:?}");
	assert_eq!(imported[0].vtxo.id, mine_id, "the owned vtxo is the one that landed");
}
