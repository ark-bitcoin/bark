
use ark_testing::{sat, TestContext};
use ark_testing::constants::BOARD_CONFIRMATIONS;

use super::helpers::{wait_for_boards_synced, wait_for_onchain_balance};

/// Verify that `GET /wallet/vtxos/{id}` returns the VTXO detail.
#[tokio::test]
async fn get_vtxo_barkd() {
	let ctx = TestContext::new("barkd/get_vtxo_barkd").await;

	let srv = ctx.captaind("server").create().await;
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(100_000)).create().await;

	wait_for_onchain_balance(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

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
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(100_000)).create().await;

	wait_for_onchain_balance(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

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
	let barkd = ctx.barkd("barkd1", &srv).funded(sat(100_000)).create().await;

	wait_for_onchain_balance(&barkd, sat(100_000)).await;
	barkd.board_all().await;
	ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
	wait_for_boards_synced(&barkd).await;

	let vtxos = barkd.vtxos(None).await;
	assert!(!vtxos.is_empty(), "should have at least one VTXO after boarding");

	let id = vtxos[0].vtxo.id.to_string();
	let encoded = barkd.get_vtxo_encoded(&id).await;

	let imported = barkd.import_vtxo(vec![encoded.encoded.0.clone()]).await;
	assert_eq!(imported.len(), 1, "should return one imported VTXO");
	assert_eq!(imported[0].vtxo.id, vtxos[0].vtxo.id, "imported VTXO id should match");
}
