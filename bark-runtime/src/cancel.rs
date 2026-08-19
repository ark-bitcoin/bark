/// A token for signaling cancellation on native platforms.
///
/// Wraps `tokio_util::sync::CancellationToken` for efficient async cancellation.
#[cfg(not(target_arch = "wasm32"))]
pub struct NativeCancellationToken {
	inner: tokio_util::sync::CancellationToken,
}

#[cfg(not(target_arch = "wasm32"))]
impl Clone for NativeCancellationToken {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
		}
	}
}

#[cfg(not(target_arch = "wasm32"))]
impl NativeCancellationToken {
	pub fn new() -> Self {
		Self {
			inner: tokio_util::sync::CancellationToken::new(),
		}
	}

	pub fn cancel(&self) {
		self.inner.cancel();
	}

	pub async fn cancelled(&self) {
		self.inner.cancelled().await;
	}
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for NativeCancellationToken {
	fn default() -> Self {
		Self::new()
	}
}

/// A token for signaling cancellation on WASM platforms.
///
/// Uses `Arc<AtomicBool>` with polling-based waiting.
#[cfg(target_arch = "wasm32")]
pub struct WasmCancellationToken {
	inner: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(target_arch = "wasm32")]
impl Clone for WasmCancellationToken {
	fn clone(&self) -> Self {
		Self {
			inner: self.inner.clone(),
		}
	}
}

#[cfg(target_arch = "wasm32")]
impl WasmCancellationToken {
	pub fn new() -> Self {
		Self {
			inner: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
		}
	}

	pub fn cancel(&self) {
		self.inner
			.store(true, std::sync::atomic::Ordering::SeqCst);
	}

	pub async fn cancelled(&self) {
		loop {
			if self.inner.load(std::sync::atomic::Ordering::SeqCst) {
				break;
			}
			crate::sleep(std::time::Duration::from_millis(10)).await;
		}
	}
}

#[cfg(target_arch = "wasm32")]
impl Default for WasmCancellationToken {
	fn default() -> Self {
		Self::new()
	}
}

#[cfg(not(target_arch = "wasm32"))]
pub use NativeCancellationToken as CancellationToken;

#[cfg(target_arch = "wasm32")]
pub use WasmCancellationToken as CancellationToken;

#[cfg(test)]
mod test {
	use std::time::Duration;

	use crate::timeout;

	use super::*;

	#[cfg(target_arch = "wasm32")]
	use wasm_bindgen_test::wasm_bindgen_test;
	#[cfg(target_arch = "wasm32")]
	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// Waiting on a cancelled token returns.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn cancelled_returns_after_cancel() {
		let token = CancellationToken::new();
		token.cancel();
		token.cancelled().await;
	}

	/// Cancelling while a waiter is pending wakes the waiter.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn cancel_wakes_a_pending_waiter() {
		let token = CancellationToken::new();
		let waiter = token.clone();
		crate::spawn(async move {
			crate::sleep(Duration::from_millis(10)).await;
			token.cancel();
		});

		timeout(Duration::from_secs(5), waiter.cancelled()).await
			.expect("cancellation should have woken the waiter");
	}

	/// A clone reports the cancellation triggered on the original token.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn clone_shares_the_cancellation_state() {
		let token = CancellationToken::new();
		let clone = token.clone();
		token.cancel();
		clone.cancelled().await;
	}

	/// Cancelling a clone also cancels the original token.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn cancelling_a_clone_cancels_the_original() {
		let token = CancellationToken::new();
		let clone = token.clone();
		clone.cancel();
		token.cancelled().await;
	}

	/// Waiting on a token that was never cancelled never returns.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn cancelled_stays_pending_without_cancel() {
		let token = CancellationToken::new();
		timeout(Duration::from_millis(50), token.cancelled()).await
			.expect_err("an uncancelled token should keep waiting");
	}

	/// A default token starts out uncancelled.
	#[cfg_attr(not(target_arch = "wasm32"), tokio::test)]
	#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
	async fn default_token_is_not_cancelled() {
		let token = CancellationToken::default();
		timeout(Duration::from_millis(50), token.cancelled()).await
			.expect_err("a fresh token should keep waiting");
		token.cancel();
		token.cancelled().await;
	}
}

