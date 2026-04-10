
/// Generates inter-lightning-node and intra-ark runner functions for a
/// **receive** test.
///
/// The test body must be an `async fn` with signature:
///
/// ```ignore
/// async fn my_test(ctx: &TestContext, lightning: &LightningPaymentSetup, srv: &Captaind, pay: impl AsyncFn(String))
/// ```
///
/// The macro produces a module with two `#[tokio::test]` functions:
///
/// - `external` — inter-lightning-node: an external lightningd pays the invoice.
/// - `intra` — intra-ark: a second bark on the same server pays the invoice.
///
/// # Example
///
/// ```ignore
/// async fn bark_can_receive_lightning(
///     ctx: &TestContext,
///     lightning: &LightningPaymentSetup,
///     srv: &Captaind,
///     pay: impl AsyncFn(String),
/// ) {
///     // shared test body ...
/// }
/// lightning_test!(bark_can_receive_lightning);
/// ```
#[macro_export]
macro_rules! lightning_test {
	($test_fn:ident) => {
		mod $test_fn {
			use super::*;

			#[tokio::test]
			async fn external() {
				let ctx = TestContext::new(
					concat!("lightningd/external_", stringify!($test_fn)),
				).await;
				let lightning = ctx.new_lightning_setup("lightningd").await;
				let srv = ctx.new_captaind_with_funds(
					"server", Some(&lightning.internal), btc(10),
				).await;

				let pay = async |invoice: String| {
					lightning.external.pay_bolt11(invoice).await;
				};

				super::$test_fn(&ctx, &lightning, &srv, pay).await;
			}

			#[tokio::test]
			async fn intra() {
				let ctx = TestContext::new(
					concat!("lightningd/intra_", stringify!($test_fn)),
				).await;
				let lightning = ctx.new_lightning_setup("lightningd").await;
				let srv = ctx.new_captaind_with_funds(
					"server", Some(&lightning.internal), btc(10),
				).await;

				let bark_sender = Arc::new(
					ctx.new_bark_with_funds("sender", &srv, btc(5)).await,
				);
				bark_sender.board_and_confirm_and_register(&ctx, btc(3)).await;

				let pay = async |invoice: String| {
					bark_sender.pay_lightning_wait(invoice, None).await;
				};

				super::$test_fn(&ctx, &lightning, &srv, pay).await;
			}
		}
	};
}
