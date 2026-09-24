//! The boundary between the relay transport and the wallet.

use std::pin::Pin;

use nostr::key::PublicKey;
use nostr::nips::nip47::{Method, NIP47Error, Request, ResponseResult};


/// The future a [RequestHandler] returns.
///
/// Not [Send] on wasm, where the runtime is single-threaded and futures that
/// touch JS values cannot cross threads. Same reason bark's other traits drop
/// the bound there.
#[cfg(not(feature = "wasm-web"))]
pub type HandlerFuture<'a> =
	Pin<Box<dyn Future<Output = Result<ResponseResult, NIP47Error>> + Send + 'a>>;

#[cfg(feature = "wasm-web")]
pub type HandlerFuture<'a> =
	Pin<Box<dyn Future<Output = Result<ResponseResult, NIP47Error>> + 'a>>;


/// Handles NWC requests that arrived over a relay.
///
/// The service does not authorise requests: anything addressed to a
/// connection's service key and decrypted with it reaches `handle`. An
/// implementation must check that `client` may call `request.method`, for
/// example with [ConnectionStore::authorise], before touching the wallet.
///
/// [ConnectionStore::authorise]: crate::ConnectionStore::authorise
///
/// The transport knows nothing about wallets and the wallet knows nothing about
/// relays, which is what lets the relay loop be tested without a wallet behind
/// it.
///
/// Returning `Err` from [RequestHandler::handle] produces a NIP-47 error
/// response. Failing to handle a request is normal operation, not a transport
/// failure, so it must not take the relay connection down.
///
/// [RequestHandler::supported_methods] feeds the kind 13194 info event. Clients
/// use it to decide what to offer the user, so it has to match what `handle`
/// actually implements: advertising a method we reject produces menu entries
/// that fail when tapped.
#[cfg(not(feature = "wasm-web"))]
pub trait RequestHandler: Send + Sync + 'static {
	fn handle(&self, client: PublicKey, request: Request) -> HandlerFuture<'_>;

	fn supported_methods(&self) -> Vec<Method>;
}

/// As above, without the thread-safety bounds wasm cannot satisfy.
#[cfg(feature = "wasm-web")]
pub trait RequestHandler: 'static {
	fn handle(&self, client: PublicKey, request: Request) -> HandlerFuture<'_>;

	fn supported_methods(&self) -> Vec<Method>;
}
