//! Nostr Wallet Connect wiring for barkd.
//!
//! The connection store, which also holds the relays, lives in the datadir next
//! to the auth token rather than in the wallet database. NWC connections are a barkd concern that the wallet
//! core never reads, and keeping them out of the wallet schema means no
//! migration for a feature the wallet does not know about.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use chrono::Utc;
use log::{debug, info, warn};
use parking_lot::Mutex;

use bark::Wallet;
use bark::fs_perms;
use bark::nwc::{Connection, ConnectionStore, NwcManager, RelayUrl};
use bark::nwc::ConnectionPersister;
use bark_json::web::{
	NwcConnectionInfo, NwcConnectionListResponse, NwcConnectionRequest, NwcConnectionResponse,
	NwcMethods, NwcRelaysResponse,
};
use bark_rest::{BoxFuture, NwcApi};
use bark_rest::error::ContextExt as _;

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


/// Exposes the NWC manager to the REST API.
///
/// Holds the shared slot rather than a manager, because the manager only exists
/// once a wallet does and a wallet can be created after the server starts.
pub struct NwcApiImpl {
	manager: SharedNwcManager,
	/// Serialises relay changes, which read the list, change it and set it back.
	relay_change: Mutex<()>,
}

impl NwcApiImpl {
	pub fn new(manager: SharedNwcManager) -> Self {
		NwcApiImpl {
			manager: manager,
			relay_change: Mutex::new(()),
		}
	}

	/// Apply `change` to the relay list, persist the result and serve on it.
	fn change_relays(
		&self,
		change: impl FnOnce(&mut Vec<RelayUrl>) -> anyhow::Result<()>,
	) -> anyhow::Result<NwcRelaysResponse> {
		let manager = require_manager(&self.manager)?;
		let _change = self.relay_change.lock();
		let mut relays = manager.relays();
		change(&mut relays)?;
		manager.set_relays(relays.clone())?;

		Ok(relays_response(&relays))
	}
}

fn relays_response(relays: &[RelayUrl]) -> NwcRelaysResponse {
	NwcRelaysResponse { relays: relays.iter().map(|r| r.to_string()).collect() }
}

/// The running manager, or a 404 when there is no wallet to serve.
fn require_manager(slot: &SharedNwcManager) -> anyhow::Result<Arc<NwcManager>> {
	slot.read().clone().not_found(
		Vec::<String>::new(),
		"NWC is not running: barkd has no wallet loaded",
	)
}

impl NwcApi for NwcApiImpl {
	fn create(
		&self,
		req: NwcConnectionRequest,
	) -> BoxFuture<anyhow::Result<NwcConnectionResponse>> {
		let slot = Arc::clone(&self.manager);
		Box::pin(async move {
			let manager = require_manager(&slot)?;

			let methods = req.methods.unwrap_or_default().allowed();

			// The URI tells the app where to find the wallet, so a connection
			// made without relays could never be reached.
			if manager.relays().is_empty() {
				return Err(anyhow::anyhow!("add one via POST /api/v1/nwc/relays first"))
					.badarg("no NWC relays are configured");
			}

			let (connection, uri) = Connection::generate(
				req.name,
				manager.relays(),
				methods.into_iter().map(String::from).collect(),
				Utc::now(),
			);
			let client_pubkey = connection.client_pubkey.clone();
			manager.add(connection)?;

			Ok(NwcConnectionResponse {
				uri: uri.to_string(),
				client_pubkey: client_pubkey,
			})
		})
	}

	fn list(&self) -> BoxFuture<anyhow::Result<NwcConnectionListResponse>> {
		let slot = Arc::clone(&self.manager);
		Box::pin(async move {
			let manager = require_manager(&slot)?;

			let connections = manager.connections().read().iter().map(|c| {
				NwcConnectionInfo {
					name: c.name.clone(),
					client_pubkey: c.client_pubkey.clone(),
					methods: NwcMethods::from_allowed(c.allowed_methods.iter().map(String::as_str)),
					created_at: c.created_at.to_rfc3339(),
				}
			}).collect();

			Ok(NwcConnectionListResponse { connections: connections })
		})
	}

	fn revoke(&self, client_pubkey: &str) -> BoxFuture<anyhow::Result<bool>> {
		let client_pubkey = client_pubkey.to_string();
		let slot = Arc::clone(&self.manager);
		Box::pin(async move {
			require_manager(&slot)?.revoke(&client_pubkey)
		})
	}

	fn relays(&self) -> BoxFuture<anyhow::Result<NwcRelaysResponse>> {
		let slot = Arc::clone(&self.manager);
		Box::pin(async move {
			Ok(relays_response(&require_manager(&slot)?.relays()))
		})
	}

	fn add_relay(&self, relay: String) -> BoxFuture<anyhow::Result<NwcRelaysResponse>> {
		let result = self.change_relays(|relays| {
			let relay = bark::nwc::parse_relays(&[relay]).badarg("invalid relay")?.remove(0);
			if !relays.contains(&relay) {
				relays.push(relay);
			}
			Ok(())
		});
		Box::pin(async move { result })
	}

	fn remove_relay(&self, relay: String) -> BoxFuture<anyhow::Result<NwcRelaysResponse>> {
		let result = self.change_relays(|relays| {
			// Parsed so that the url matches however it was spelled when added.
			let parsed = bark::nwc::parse_relays(&[relay.clone()]).ok().map(|mut r| r.remove(0));
			let before = relays.len();
			relays.retain(|r| Some(r) != parsed.as_ref());
			if relays.len() == before {
				return None.not_found([&relay], "no such NWC relay");
			}
			Ok(())
		});
		Box::pin(async move { result })
	}
}


#[cfg(test)]
mod test {
	use super::*;

	/// A method is granted or turned off through its field in NwcMethods, so a
	/// method the wallet learns to answer needs a field there too.
	#[test]
	fn every_supported_method_has_a_field() {
		let mut fields = NwcMethods::default().allowed();
		fields.sort();
		let mut supported = bark::nwc::dispatch::supported_methods().iter()
			.map(|m| m.to_string())
			.collect::<Vec<_>>();
		supported.sort();
		assert_eq!(fields, supported);
	}

	/// Relays are only stored in nwc.json, so they have to come back from it
	/// after a restart along with the connections.
	#[test]
	fn relays_survive_a_restart() {
		let dir = std::env::temp_dir().join(format!("barkd-nwc-test-{}", std::process::id()));
		std::fs::create_dir_all(&dir).unwrap();

		let relay = RelayUrl::parse("wss://relay.example.com").unwrap();
		let mut store = ConnectionStore::new();
		store.set_relays(vec![relay.clone()]);
		FileConnectionPersister::new(&dir).save(&store).unwrap();

		let loaded = load_connections(&dir).unwrap();
		assert_eq!(loaded.relays(), &[relay]);

		let _ = std::fs::remove_dir_all(&dir);
	}
}
