#[cfg(not(feature = "wasm-web"))]
pub use std::time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(not(feature = "wasm-web"))]
pub use tokio::time::{sleep, timeout, error::Elapsed};

#[cfg(feature = "wasm-web")]
pub use web_time::{Instant, SystemTime, UNIX_EPOCH};
#[cfg(feature = "wasm-web")]
pub use self::wasm_impl::{sleep, timeout, Elapsed};



/// Wall-clock reading. On native this is `std::time::SystemTime::now()`;
/// under the `wasm-web` feature it goes through `Date.now()` so it doesn't
/// panic on `wasm32-unknown-unknown`.
pub fn now() -> SystemTime {
	SystemTime::now()
}

pub fn timestamp_secs() -> u64 {
	now().duration_since(UNIX_EPOCH)
		.expect("time went backwards")
		.as_secs()
}

#[cfg(feature = "wasm-web")]
mod wasm_impl {
	use std::future::Future;
	use std::pin::pin;
	use std::time::Duration;

	use futures::future::{select, Either};
	use wasm_bindgen::prelude::*;
	use wasm_bindgen_futures::JsFuture;

	pub async fn sleep(duration: Duration) {
		// `setTimeout` takes an `i32` millisecond delay; clamp to be safe.
		let millis = duration.as_millis().min(i32::MAX as u128) as f64;
		let promise = js_sys::Promise::new(&mut |resolve, _reject| {
			let global = js_sys::global();
			let set_timeout = js_sys::Reflect::get(&global, &"setTimeout".into())
				.expect("setTimeout missing on JS global")
				.dyn_into::<js_sys::Function>()
				.expect("setTimeout is not a function");
			let _ = set_timeout.call2(&JsValue::NULL, &resolve, &JsValue::from_f64(millis));
		});
		let _ = JsFuture::from(promise).await;
	}

	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub struct Elapsed;

	impl std::fmt::Display for Elapsed {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("deadline has elapsed")
		}
	}
	impl std::error::Error for Elapsed {}

	pub async fn timeout<F: Future>(duration: Duration, future: F)
		-> Result<F::Output, Elapsed>
	{
		let s = pin!(sleep(duration));
		let f = pin!(future);
		match select(f, s).await {
			Either::Left((out, _)) => Ok(out),
			Either::Right(((), _)) => Err(Elapsed),
		}
	}
}
