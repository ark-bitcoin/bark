use std::time::Duration;
use std::future::Future;

/// Timeout error.
///
/// On native platforms, wraps `tokio::time::error::Elapsed`.
/// On WASM, uses a custom implementation.
#[cfg(not(target_arch = "wasm32"))]
pub use tokio::time::error::Elapsed;

#[cfg(target_arch = "wasm32")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Elapsed;

#[cfg(target_arch = "wasm32")]
impl std::fmt::Display for Elapsed {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str("deadline has elapsed")
	}
}

#[cfg(target_arch = "wasm32")]
impl std::error::Error for Elapsed {}

/// Timeout a future.
///
/// On native platforms, uses `tokio::time::timeout`.
/// On WASM, uses `futures::future::select`.
pub async fn timeout<F: Future>(duration: Duration, future: F)
	-> Result<F::Output, Elapsed>
{
	#[cfg(not(target_arch = "wasm32"))]
	{
		tokio::time::timeout(duration, future).await
	}

	#[cfg(target_arch = "wasm32")]
	{
		use std::pin::pin;
		use futures::future::{select, Either};

		let s = pin!(crate::sleep(duration));
		let f = pin!(future);
		match select(f, s).await {
			Either::Left((out, _)) => Ok(out),
			Either::Right(((), _)) => Err(Elapsed),
		}
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;
	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// A future that finishes in time yields its output.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn returns_the_output_of_a_fast_future() {
		let out = timeout(Duration::from_secs(5), async { "done" }).await
			.expect("an immediate future cannot time out");
		assert_eq!("done", out);
	}

	/// A future that sleeps less than the deadline still yields its output.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn returns_the_output_of_a_future_that_sleeps_briefly() {
		let out = timeout(Duration::from_secs(5), async {
			crate::sleep(Duration::from_millis(10)).await;
			7
		}).await.expect("a brief sleep fits well within the deadline");
		assert_eq!(7, out);
	}

	/// A future that outlives the deadline is abandoned with an error.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn errors_when_the_future_outlives_the_deadline() {
		timeout(Duration::from_millis(50), async {
			crate::sleep(Duration::from_secs(60)).await;
		}).await.expect_err("the deadline should have fired first");
	}

	/// A zero deadline errors instead of waiting for the future.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn errors_on_a_zero_deadline() {
		timeout(Duration::ZERO, async {
			crate::sleep(Duration::from_secs(60)).await;
		}).await.expect_err("a zero deadline is already past");
	}

	/// The timeout error explains that the deadline passed.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn elapsed_error_mentions_the_deadline() {
		let err = timeout(Duration::from_millis(10), async {
			crate::sleep(Duration::from_secs(60)).await;
		}).await.unwrap_err();
		assert!(err.to_string().contains("elapsed"), "{}", err);
	}
}

