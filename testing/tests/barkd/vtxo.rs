
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

/// Verify that `GET /wallet/vtxos/{id}` returns the VTXO detail.
#[tokio::test]
async fn get_vtxo_barkd() {
	let ctx = TestContext::new("barkd/get_vtxo_barkd").await;

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

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

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

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

	let srv = ctx.new_captaind("server", None).await;
	let barkd = ctx.new_barkd("barkd1", &srv).await;

	ctx.fund_barkd(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;

	// Get the encoded VTXO via the encoded endpoint.
	let vtxos = barkd.vtxos(None).await;
	assert!(!vtxos.is_empty(), "should have at least one VTXO after boarding");

	let id = vtxos[0].vtxo.id.to_string();
	let encoded = barkd.get_vtxo_encoded(&id).await;

	// Re-import the same VTXO (idempotent).
	let imported = barkd.import_vtxo(vec![encoded.encoded.0.clone()]).await;
	assert_eq!(imported.len(), 1, "should return one imported VTXO");
	assert_eq!(imported[0].vtxo.id, vtxos[0].vtxo.id, "imported VTXO id should match");
}
