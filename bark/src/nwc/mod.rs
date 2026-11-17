//! Binding between a bark wallet and Nostr Wallet Connect (NIP-47).
//!
//! The protocol, the relay transport and the rules deciding what a connection
//! may do all live in [bark_nwc]. What is here is the part that needs a wallet:
//! [dispatch::WalletHandler], which answers NIP-47 requests by calling into
//! one.
//!
//! Behind the `nwc` feature, which is off by default. bark_nwc pulls in the
//! nostr stack, including its own secp256k1 and bitcoin_hashes versions that do
//! not match the ones bark uses. Keys therefore cross between the two as raw
//! bytes, which costs nothing because NWC connection keys are deliberately
//! unrelated to wallet keys.
//!
//! The listener runs as part of [Wallet::start_daemon](crate::Wallet::start_daemon)
//! and stops with it, so NWC is tied to the wallet rather than to whichever
//! process is hosting it.
//!
//! Connections are persisted by the caller through [ConnectionPersister],
//! because where they belong differs by embedder: a daemon has a datadir, a
//! browser wallet does not.

pub mod dispatch;

pub use self::dispatch::WalletHandler;

// Re-exported so an embedder reaches NWC through one import path, rather than
// having to know which of the two crates each name came from.
pub use bark_nwc::{
	amount, connection, handler, persist, service,
	Connection, ConnectionPersister, ConnectionStore,
	handler::RequestHandler,
	parse_relays,
};
// Relays cross the API as this type, so an embedder can name it without
// depending on nostr itself.
pub use nostr::types::RelayUrl;

/// The NWC manager a bark wallet serves through.
///
/// [bark_nwc::manager::NwcManager] is generic over the handler, because running
/// relay services is not wallet work. This is that machinery bound to the one
/// handler that answers out of a wallet.
pub type NwcManager = bark_nwc::manager::NwcManager<WalletHandler>;
