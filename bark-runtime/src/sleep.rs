use std::time::Duration;

/// Sleep for the given duration.
///
/// On native platforms, uses `tokio::time::sleep`.
/// On WASM, uses `gloo_timers::future::sleep`.
pub async fn sleep(duration: Duration) {
	#[cfg(not(target_arch = "wasm32"))]
	{
		tokio::time::sleep(duration).await;
	}

	#[cfg(target_arch = "wasm32")]
	{
		gloo_timers::future::sleep(duration).await;
	}
}

#[cfg(test)]
mod test {
	use super::*;

	use crate::Instant;

	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;
	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// Sleeping returns only once the requested duration has passed.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn sleep_waits_for_the_duration() {
		let start = Instant::now();
		sleep(Duration::from_millis(50)).await;
		assert!(start.elapsed() >= Duration::from_millis(50), "{:?}", start.elapsed());
	}

	/// A zero-duration sleep returns.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn zero_sleep_returns() {
		sleep(Duration::ZERO).await;
	}
}

