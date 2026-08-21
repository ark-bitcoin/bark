//! Source of blockchain tip.

use std::future::Future;

use bark_runtime::{MaybeSend, MaybeSync};
use bitcoin_ext::BlockRef;

/// A backend the tip watcher can fetch the current chain tip from.
///
/// Implementors can use a plain `async fn tip_ref`. The [MaybeSend]
/// bounds require [Send] futures on native platforms only; on WASM the
/// runtime is single-threaded and HTTP client futures aren't [Send].
pub trait TipSource: MaybeSend + MaybeSync {
	fn tip_ref(&self) -> impl Future<Output = anyhow::Result<BlockRef>> + MaybeSend;
}
