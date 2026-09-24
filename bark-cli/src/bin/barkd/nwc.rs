//! Nostr Wallet Connect wiring for barkd.
//!
//! The connection store, which also holds the relays, lives in the datadir next
//! to the auth token rather than in the wallet database. NWC connections are a barkd concern that the wallet
//! core never reads, and keeping them out of the wallet schema means no
//! migration for a feature the wallet does not know about.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use log::{debug, info, warn};

use bark::Wallet;
use bark::fs_perms;
use bark::nwc::{Connection, ConnectionStore, NwcManager};
use bark::nwc::ConnectionPersister;

use crate::SharedNwcManager;


/// Filename of the connection store, relays included, inside the datadir.
pub const NWC_CONNECTIONS_FILE: &str = "nwc.json";


/// Writes the connection store to the datadir.
///
/// The file holds per-connection service secrets, so it is written owner-only
/// and atomically: a torn write would lose every connection.
pub struct FileConnectionPersister {
	path: PathBuf,
}

impl FileConnectionPersister {
	pub fn new(datadir: &PathBuf) -> Self {
		FileConnectionPersister { path: datadir.join(NWC_CONNECTIONS_FILE) }
	}
}

impl ConnectionPersister for FileConnectionPersister {
	fn save(&self, store: &ConnectionStore) -> anyhow::Result<()> {
		let json = serde_json::to_vec_pretty(store)
			.context("failed to serialise NWC connections")?;
		fs_perms::write_atomic_owner_only(&self.path, &json)
	}
}

/// Load the connection store from the datadir, or an empty one if absent.
fn load_connections(datadir: &PathBuf) -> anyhow::Result<ConnectionStore> {
	let path = datadir.join(NWC_CONNECTIONS_FILE);
	if !path.exists() {
		return Ok(ConnectionStore::new());
	}

	let bytes = std::fs::read(&path)
		.with_context(|| format!("failed to read {}", path.display()))?;
	// Failing to parse is fatal rather than starting fresh: an empty store
	// would silently revoke every connection.
	serde_json::from_slice(&bytes)
		.with_context(|| format!("failed to parse {}", path.display()))
}


/// Pick the rustls crypto provider for this process.
///
/// Connecting to a relay over `wss://` goes through rustls' process-level
/// default provider. rustls only infers one when exactly one provider feature
/// is enabled, and a workspace build enables both: bark-cli's own graph uses
/// ring, while bark-rest-client and the server pull in aws-lc-rs through
/// reqwest. Feature unification then leaves rustls unable to choose, and it
/// panics on the first handshake rather than at startup.
///
/// Installing ring explicitly makes the choice the same however barkd was
/// built. Nothing else in the process relies on the default, so this only
/// affects code paths that would otherwise panic.
fn install_crypto_provider() {
	// An error means something already installed a provider, which is just as
	// good as installing one here.
	if rustls::crypto::ring::default_provider().install_default().is_err() {
		debug!("A rustls crypto provider was already installed");
	}
}

/// Register NWC on the wallet.
///
/// Relays are stored with the connections. With none, nothing is served until
/// one is added. Serving starts when the daemon does.
pub fn register(wallet: &Wallet, datadir: &PathBuf) -> anyhow::Result<Arc<NwcManager>> {
	install_crypto_provider();

	let connections = load_connections(datadir)?;
	let persister = Arc::new(FileConnectionPersister::new(datadir));

	let manager = wallet.init_nwc(connections, persister)?;
	if manager.relays().is_empty() {
		info!("NWC has no relays configured, so nothing is served; add one via \
			POST /api/v1/nwc/relays");
	} else {
		info!("NWC enabled on {} relay(s)", manager.relays().len());
		if manager.connections().read().is_empty() {
			warn!("NWC is enabled but no connections exist yet — create one via \
				POST /api/v1/nwc/connections");
		}
	}

	Ok(manager)
}
