//! Named locks backed by the browser's
//! [Web Locks API](https://developer.mozilla.org/docs/Web/API/Web_Locks_API)
//! (`navigator.locks`).
//!
//! # Safety scope
//!
//! Prevents concurrent access by callers within a single **browser
//! origin**, including:
//!
//! - all async tasks in the current document;
//! - other same-origin tabs and dedicated/shared workers in the same
//!   browser profile.
//!
//! Gives no guarantees across:
//!
//! - different browsers or different user profiles;
//! - private / incognito windows (which use a separate lock universe);
//! - cross-origin iframes (a different origin = a different lock
//!   universe).
//!
//! # Platform support
//!
//! `wasm32` targets running in a browser context that exposes
//! `navigator.locks`. Supported in all modern evergreen browsers
//! (Chromium, Firefox, Safari).
//!
//! Construction does not probe for support; the first `try_lock` /
//! `lock` call returns an error if `globalThis.navigator` or
//! `navigator.locks` is missing — for example in a non-secure context
//! (must be HTTPS or `localhost`), inside some Worker types, or in
//! environments like `wasi`-flavored wasm runtimes.
//!
//! # When to use
//!
//! - You are targeting a browser on `wasm32`. This is the only
//!   [`super::LockManager`] implementation available there.

use anyhow::{anyhow, bail, Context};
use futures::channel::oneshot;
use js_sys::{Function, Object, Reflect};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::future_to_promise;

use super::{LockGuard, LockManager, key::validate_key};

pub struct WebLockManager;

impl WebLockManager {
	pub fn new() -> Self {
		Self
	}
}

impl Default for WebLockManager {
	fn default() -> Self { Self::new() }
}

impl std::fmt::Debug for WebLockManager {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WebLockManager").finish()
	}
}

#[async_trait::async_trait]
impl LockManager for WebLockManager {
	async fn try_lock(&self, key: &str) -> Option<Box<dyn LockGuard>> {
		if let Err(e) = validate_key(key) {
			log::warn!("rejecting lock key {:?}: {:#}", key, e);
			return None;
		}
		match request(key).await {
			Ok(Some(g)) => Some(Box::new(g)),
			// Lock is held by another caller — `ifAvailable` returned null.
			Ok(None) => None,
			Err(e) => {
				log::warn!("Web Locks request for {:?} failed: {:#}", key, e);
				None
			}
		}
	}
}

struct WebLockGuard {
	release: Option<oneshot::Sender<()>>,
}

impl Drop for WebLockGuard {
	fn drop(&mut self) {
		if let Some(tx) = self.release.take() {
			let _ = tx.send(());
		}
	}
}

impl LockGuard for WebLockGuard {}

impl std::fmt::Debug for WebLockGuard {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("WebLockGuard").finish()
	}
}

async fn request(name: &str) -> anyhow::Result<Option<WebLockGuard>> {
	let jsval_err = |v: JsValue| anyhow!("JS error: {:?}", v);

	// Resolve navigator.locks.request.
	let navigator = Reflect::get(&js_sys::global(), &JsValue::from_str("navigator"))
		.map_err(jsval_err)
		.context("globalThis.navigator missing")?;
	if navigator.is_undefined() || navigator.is_null() {
		bail!("globalThis.navigator is not available in this environment");
	}
	let locks = Reflect::get(&navigator, &JsValue::from_str("locks"))
		.map_err(jsval_err)
		.context("navigator.locks missing")?;
	if locks.is_undefined() || locks.is_null() {
		bail!("Web Locks API not available (navigator.locks missing)");
	}
	let request_fn: Function = Reflect::get(&locks, &JsValue::from_str("request"))
		.map_err(jsval_err)
		.context("navigator.locks.request lookup failed")?
		.dyn_into()
		.map_err(|_| anyhow!("navigator.locks.request is not a function"))?;

	// Two channels bridge the callback-shaped Web Locks API to async Rust:
	//   `granted` — fires when the callback is invoked, so `request().await` returns.
	//   `release` — held by WebLockGuard; firing it resolves the callback's
	//     deferred promise, which is the browser's signal to release the lock.
	let (granted_tx, granted_rx) = oneshot::channel::<bool>();
	let (release_tx, release_rx) = oneshot::channel::<()>();

	let cb = Closure::once_into_js(move |lock: JsValue| -> JsValue {
		if lock.is_null() {
			let _ = granted_tx.send(false);
			return JsValue::UNDEFINED;
		}
		let _ = granted_tx.send(true);
		future_to_promise(async move {
			let _ = release_rx.await;
			Ok(JsValue::UNDEFINED)
		}).into()
	});

	// Call navigator.locks.request(name, { ifAvailable: true }, cb). The
	// `ifAvailable` option makes this non-blocking: if the lock is held,
	// the callback is invoked with `null` instead of waiting.
	let opts = Object::new();
	Reflect::set(&opts, &JsValue::from_str("ifAvailable"), &JsValue::TRUE)
		.map_err(jsval_err)?;
	request_fn.call3(&locks, &JsValue::from_str(name), &opts.into(), &cb)
		.map_err(jsval_err)
		.context("navigator.locks.request threw")?;

	let granted = granted_rx.await
		.context("Web Locks: granted channel closed unexpectedly")?;

	if granted {
		Ok(Some(WebLockGuard { release: Some(release_tx) }))
	} else {
		Ok(None)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use wasm_bindgen_test::wasm_bindgen_test;

	wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

	/// Yield to the JS event loop so queued microtasks/macrotasks run.
	/// Needed after dropping a `WebLockGuard`: the drop fires a oneshot
	/// that resolves a JS promise that the browser uses as its signal
	/// to release the lock, all asynchronously.
	async fn yield_to_browser() {
		let promise = js_sys::Promise::new(&mut |resolve, _reject| {
			let global = js_sys::global();
			let set_timeout = js_sys::Reflect::get(&global, &"setTimeout".into())
				.expect("setTimeout missing")
				.dyn_into::<js_sys::Function>()
				.expect("setTimeout is not a function");
			let _ = set_timeout.call2(&JsValue::NULL, &resolve, &JsValue::from_f64(0.0));
		});
		let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
	}

	#[wasm_bindgen_test]
	async fn try_lock_and_release() {
		let mgr = WebLockManager::new();

		// Take the lock.
		let g = mgr.try_lock("bark.test.web").await
			.expect("first acquisition should succeed");

		// Second acquisition is refused.
		let busy = mgr.try_lock("bark.test.web").await;
		assert!(busy.is_none(), "second try_lock should be blocked");

		// Release and yield so the browser actually processes it.
		drop(g);
		yield_to_browser().await;

		let g2 = mgr.try_lock("bark.test.web").await
			.expect("acquisition after release should succeed");
		drop(g2);
	}

	#[wasm_bindgen_test]
	async fn distinct_keys_dont_block() {
		let mgr = WebLockManager::new();
		let _a = mgr.try_lock("bark.test.web.a").await.unwrap();
		let _b = mgr.try_lock("bark.test.web.b").await.unwrap();
	}
}
