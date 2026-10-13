//! Persistence of the connection store.

use crate::connection::ConnectionStore;

/// Persists the connection store whenever it changes.
///
/// A connection that is not persisted stops working after a restart, so any
/// wallet enabling NIP-47 must implement this trait.
pub trait ConnectionPersister: Send + Sync + 'static {
	fn save(&self, store: &ConnectionStore) -> anyhow::Result<()>;
}
