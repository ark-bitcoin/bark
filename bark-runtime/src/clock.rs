//! Clock types that also work in the browser.
//!
//! `std::time::Instant` and `std::time::SystemTime` panic on
//! `wasm32-unknown-unknown`, so on WASM these come from `web_time`, which
//! reads the JS clocks instead.

#[cfg(not(target_arch = "wasm32"))]
pub use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(target_arch = "wasm32")]
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};

/// Wall-clock reading. On native this is `std::time::SystemTime::now()`;
/// on WASM it goes through `Date.now()` so it doesn't panic on
/// `wasm32-unknown-unknown`.
pub fn now() -> SystemTime {
	SystemTime::now()
}

/// The current unix timestamp in seconds.
pub fn timestamp_secs() -> u64 {
	now().duration_since(UNIX_EPOCH)
		.expect("time went backwards")
		.as_secs()
}

#[cfg(test)]
mod test {
	use std::time::Duration;

	use super::*;

	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;
	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// The timestamp is a plausible current unix time.
	#[cfg_attr(not(target_arch = "wasm32"), test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	fn timestamp_is_a_recent_unix_time() {
		let ts = timestamp_secs();
		assert!(ts > 1_750_000_000, "{}", ts);
	}

	/// The wall clock never reads earlier than the unix epoch.
	#[cfg_attr(not(target_arch = "wasm32"), test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	fn wall_clock_is_after_the_epoch() {
		assert!(now().duration_since(UNIX_EPOCH).is_ok());
	}

	/// An instant reports the time that passed since it was taken.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn instant_measures_elapsed_time() {
		let start = Instant::now();
		crate::sleep(Duration::from_millis(20)).await;
		assert!(start.elapsed() >= Duration::from_millis(20), "{:?}", start.elapsed());
	}
}

