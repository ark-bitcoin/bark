use ark_testing::{TestContext, sat};

use bark::exit::ExitError;

/// A VTXO consumed outside the exit flow (e.g. spent via arkoor) has no exit entry; the
/// estimate must still reject it as already spent.
#[tokio::test]
async fn exit_estimate_rejects_spent_vtxo() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_spent_vtxo").await;
	let srv = ctx.captaind("server").create().await;

	let sender = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let receiver = ctx.bark_sdk("bark2", &srv).create().await;

	let [boarded] = sender.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let spent_id = boarded.vtxo.id();

	let address = receiver.new_address().await.expect("new address");
	sender.send_arkoor_payment(&address, sat(100_000)).await.expect("arkoor send");

	let err = sender.estimate_emergency_exit_fee(&[spent_id], None, None, None).await
		.expect_err("estimating a spent VTXO must fail");
	assert_eq!(err, ExitError::VtxoAlreadySpent { vtxo: spent_id });
}

/// An invalid fee margin is a typed error, not a panic — including one that scales the fee out
/// of range.
#[tokio::test]
async fn exit_estimate_rejects_invalid_fee_margin() {
	let ctx = TestContext::new("bark_sdk/exit_estimate_rejects_invalid_fee_margin").await;
	let srv = ctx.captaind("server").create().await;
	let wallet = ctx.bark_sdk("bark", &srv).boarded(sat(400_000)).create().await;
	let [vtxo] = wallet.vtxos().await.expect("list vtxos")
		.try_into().expect("expected exactly one boarded vtxo");
	let vtxo_id = vtxo.vtxo.id();

	for margin in [f64::NAN, f64::INFINITY, -0.5, f64::MAX] {
		let err = wallet.estimate_emergency_exit_fee(&[vtxo_id], None, None, Some(margin)).await
			.expect_err("an invalid fee margin must be rejected");
		assert!(matches!(err, ExitError::InvalidFeeMargin { .. }), "{:?}", err);
	}
}
