//! Runtime abstractions for native and WASM compatibility.
//!
//! This crate provides abstractions over async runtime functionality
//! to support both native (tokio) and WASM (wasm-bindgen) environments.

pub mod cancel;
pub mod clock;
pub mod sleep;
pub mod task;
pub mod timeout;

pub use cancel::CancellationToken;
pub use clock::{now, timestamp_secs, Instant, SystemTime, UNIX_EPOCH};
pub use sleep::sleep;
pub use task::spawn;
pub use timeout::{timeout, Elapsed};

/// A trait that requires [Send] on native platforms and nothing on WASM,
/// where the runtime is single-threaded and futures often aren't [Send].
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSend: Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Send> MaybeSend for T {}

/// A trait that requires [Send] on native platforms and nothing on WASM,
/// where the runtime is single-threaded and futures often aren't [Send].
#[cfg(target_arch = "wasm32")]
pub trait MaybeSend {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSend for T {}

/// A trait that requires [Sync] on native platforms and nothing on WASM.
#[cfg(not(target_arch = "wasm32"))]
pub trait MaybeSync: Sync {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: Sync> MaybeSync for T {}

/// A trait that requires [Sync] on native platforms and nothing on WASM.
#[cfg(target_arch = "wasm32")]
pub trait MaybeSync {}
#[cfg(target_arch = "wasm32")]
impl<T> MaybeSync for T {}
