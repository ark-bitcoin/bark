//! Persistence of the connection store.

use crate::connection::ConnectionStore;

/// Persists the connection store whenever it changes.
///
/// The store holds the relays as well as the connections. A connection or relay
/// that is not persisted is gone after a restart, so any wallet enabling NIP-47
/// must implement this trait.
pub trait ConnectionPersister: Send + Sync + 'static {
	fn save(&self, store: &ConnectionStore) -> anyhow::Result<()>;
}
