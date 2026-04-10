
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
/// An optional config closure can be passed to customize the server:
///
/// ```ignore
/// lightning_test!(my_test, |cfg| {
///     cfg.invoice_check_interval = Duration::from_secs(1);
/// });
/// ```
#[macro_export]
macro_rules! lightning_test {
	($test_fn:ident) => {
		$crate::lightning_test!($test_fn, |_cfg| {});
	};
	($test_fn:ident, |$cfg:ident| $cfg_body:block) => {
		mod $test_fn {
			use super::*;

			#[tokio::test]
			async fn external() {
				let ctx = TestContext::new(
					concat!("lightningd/external_", stringify!($test_fn)),
				).await;
				let lightning = ctx.new_lightning_setup("lightningd").await;
				let srv = ctx.new_captaind_with_cfg(
					"server", Some(&lightning.internal), |$cfg| $cfg_body,
				).await;
				ctx.fund_captaind(&srv, btc(10)).await;

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
				let srv = ctx.new_captaind_with_cfg(
					"server", Some(&lightning.internal), |$cfg| $cfg_body,
				).await;
				ctx.fund_captaind(&srv, btc(10)).await;

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
