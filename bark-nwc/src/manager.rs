//! Runs one NWC service per connection and keeps them in step with the store.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Context;
use log::{info, warn};
use nostr::types::RelayUrl;
use parking_lot::{Mutex, RwLock};
use tokio_util::sync::CancellationToken;

use crate::connection::{Connection, ConnectionStore};
use crate::handler::RequestHandler;
use crate::persist::ConnectionPersister;
use crate::service::NwcService;


/// Owns the running services and the connection store they are derived from.
///
/// Each connection has its own service keypair, so each needs its own relay
/// subscription. Revoking a connection therefore has to stop its service, not
/// only drop it from the store, or the app would keep getting answers.
///
/// Generic over the handler, because deciding what a request means is the
/// host's job: every service answers through the same one.
pub struct NwcManager<H> {
	handler: Arc<H>,
	/// The connections and the relays they are served on. The relays change
	/// through [NwcManager::set_relays], so each service start reads them.
	connections: Arc<RwLock<ConnectionStore>>,
	persister: Arc<dyn ConnectionPersister>,
	/// Keyed by client pubkey, matching [ConnectionStore].
	running: RwLock<HashMap<String, RunningService>>,
	/// Held across the whole of add and revoke, so a revoke cannot slip in
	/// between an add persisting a connection and starting its service.
	operation: Mutex<()>,
	/// Set between [NwcManager::start_all] and [NwcManager::stop_all], so a
	/// relay change only brings services up while the host is serving.
	serving: AtomicBool,
	shutdown: CancellationToken,
}

/// A service task, and what is needed to stop it.
///
/// Cancelling the token is what stops the service; the join handle only lets a
/// native build abort one that is still inside its startup connect rather than
/// waiting for it to reach the select loop. wasm has no join handles, so there
/// it stops a fraction later.
#[cfg(not(feature = "wasm-web"))]
struct RunningService {
	shutdown: CancellationToken,
	handle: tokio::task::JoinHandle<()>,
}

#[cfg(feature = "wasm-web")]
struct RunningService {
	shutdown: CancellationToken,
}

impl<H: RequestHandler> NwcManager<H> {
	/// The store is shared rather than owned, because the handler has to read
	/// and charge the same connections the manager serves.
	pub fn new(
		handler: Arc<H>,
		connections: Arc<RwLock<ConnectionStore>>,
		persister: Arc<dyn ConnectionPersister>,
	) -> Arc<Self> {
		Arc::new(NwcManager {
			handler: handler,
			connections: connections,
			persister: persister,
			running: RwLock::new(HashMap::new()),
			operation: Mutex::new(()),
			serving: AtomicBool::new(false),
			// Owned rather than supplied: the manager's lifetime is the
			// daemon's, and stop_all is what ends it.
			shutdown: CancellationToken::new(),
		})
	}

	pub fn connections(&self) -> &Arc<RwLock<ConnectionStore>> {
		&self.connections
	}

	pub fn relays(&self) -> Vec<RelayUrl> {
		self.connections.read().relays().to_vec()
	}

	/// Persist `relays` and serve every connection on them from now on.
	///
	/// Running services are restarted on the new relays. A connection URI
	/// names the relays it was created with, so an app only follows a relay
	/// change as far as its URI does: dropping every relay it knows cuts it off
	/// until it is given a new connection.
	pub fn set_relays(self: &Arc<Self>, relays: Vec<RelayUrl>) -> anyhow::Result<()> {
		let _operation = self.operation.lock();
		let existing = {
			let mut connections = self.connections.write();
			let rollback = connections.clone();
			connections.set_relays(relays);
			if let Err(e) = self.persister.save(&connections) {
				// Relays that were not written down would be served now and
				// gone after a restart.
				*connections = rollback;
				return Err(e).context("failed to persist NWC relays");
			}
			connections.iter().cloned().collect::<Vec<_>>()
		};

		self.stop_services();
		if !self.serving.load(Ordering::SeqCst) {
			return Ok(());
		}
		for connection in existing {
			self.start(&connection);
		}
		Ok(())
	}

	/// Start a service for every connection already in the store.
	pub fn start_all(self: &Arc<Self>) {
		// A revoke must not land between the snapshot and its services starting.
		let _operation = self.operation.lock();
		self.serving.store(true, Ordering::SeqCst);
		let existing = self.connections.read().iter().cloned().collect::<Vec<_>>();
		if existing.is_empty() {
			info!("No NWC connections configured, nothing to serve");
			return;
		}
		for connection in existing {
			self.start(&connection);
		}
	}

	/// Spawn the relay service for one connection.
	///
	/// A service that fails to start is logged and skipped rather than taking
	/// the daemon down: one unreachable relay must not stop the wallet.
	fn start(self: &Arc<Self>, connection: &Connection) {
		let relays = self.connections.read().relays().to_vec();
		if relays.is_empty() {
			info!("No NWC relays configured, not serving connection {}", connection.name);
			return;
		}

		let keys = match connection.service_keys() {
			Ok(keys) => keys,
			Err(e) => {
				warn!("NWC connection {} has an unusable key, skipping: {:#}", connection.name, e);
				return;
			},
		};

		let service = NwcService::new(keys, relays, Arc::clone(&self.handler));

		// Child of the manager token, so stop_all stops every service
		// at once, while a revoke stops just this one.
		let shutdown = self.shutdown.child_token();
		let name = connection.name.clone();
		let task = {
			let shutdown = shutdown.clone();
			async move {
				if let Err(e) = service.run(shutdown).await {
					warn!("NWC service for {name} stopped with an error: {e:#}");
				}
			}
		};

		// crate::spawn returns a join handle natively and nothing on
		// wasm, so the running entry differs by target.
		#[cfg(not(feature = "wasm-web"))]
		let running = RunningService {
			shutdown: shutdown,
			handle: crate::spawn(task),
		};
		#[cfg(feature = "wasm-web")]
		let running = {
			crate::spawn(task);
			RunningService { shutdown: shutdown }
		};

		// revoke and stop_all both work from this map, so a displaced entry
		// could never be stopped again.
		let displaced = self.running.write().insert(connection.client_pubkey.clone(), running);
		if let Some(previous) = displaced {
			warn!("Replacing the running NWC service for connection {}", connection.name);
			previous.shutdown.cancel();
			#[cfg(not(feature = "wasm-web"))]
			previous.handle.abort();
		}

		info!("Started NWC service for connection {}", connection.name);
	}

	/// Register a connection, persist it and serve it if the manager is
	/// serving. Otherwise [NwcManager::start_all] serves it.
	pub fn add(self: &Arc<Self>, connection: Connection) -> anyhow::Result<()> {
		let _operation = self.operation.lock();
		{
			let mut connections = self.connections.write();
			let rollback = connections.clone();
			connections.insert(connection.clone());
			if let Err(e) = self.persister.save(&connections) {
				// A connection that was not written down would be served now
				// and gone after a restart.
				*connections = rollback;
				return Err(e).context("failed to persist NWC connection");
			}
		}
		if self.serving.load(Ordering::SeqCst) {
			self.start(&connection);
		}
		Ok(())
	}

	/// Revoke a connection: stop its service and forget it.
	///
	/// Returns whether there was a connection to revoke.
	pub fn revoke(&self, client_pubkey: &str) -> anyhow::Result<bool> {
		let _operation = self.operation.lock();
		let removed = {
			let mut connections = self.connections.write();
			let rollback = connections.clone();
			let removed = connections.remove(client_pubkey).is_some();
			if removed {
				if let Err(e) = self.persister.save(&connections) {
					// A revoke that was not written down has to stay revocable.
					*connections = rollback;
					return Err(e).context("failed to persist NWC connection removal");
				}
			}
			removed
		};

		// Stop the service regardless of what the store said, so a desynced
		// service cannot keep answering for a connection that is gone.
		if let Some(service) = self.running.write().remove(client_pubkey) {
			service.shutdown.cancel();
			#[cfg(not(feature = "wasm-web"))]
			service.handle.abort();
		}

		Ok(removed)
	}

	/// Stop every running service.
	pub fn stop_all(&self) {
		self.serving.store(false, Ordering::SeqCst);
		self.stop_services();
	}

	fn stop_services(&self) {
		for (_, service) in self.running.write().drain() {
			service.shutdown.cancel();
			#[cfg(not(feature = "wasm-web"))]
			service.handle.abort();
		}
	}
}


#[cfg(test)]
mod test {
	use nostr::key::PublicKey;
	use nostr::nips::nip47::{Method, Request};

	use crate::connection::Connection;
	use crate::handler::HandlerFuture;

	use super::*;

	/// Never reached: these tests stop before any request arrives.
	struct StubHandler;

	impl RequestHandler for StubHandler {
		fn handle(&self, _client: PublicKey, _request: Request) -> HandlerFuture<'_> {
			unimplemented!("the store is never reached in these tests")
		}

		fn supported_methods(&self) -> Vec<Method> {
			vec![Method::GetBalance]
		}
	}

	struct FailingPersister;

	impl ConnectionPersister for FailingPersister {
		fn save(&self, _store: &ConnectionStore) -> anyhow::Result<()> {
			Err(anyhow::anyhow!("the disk is full"))
		}
	}

	struct NoopPersister;

	impl ConnectionPersister for NoopPersister {
		fn save(&self, _store: &ConnectionStore) -> anyhow::Result<()> {
			Ok(())
		}
	}

	fn manager() -> (Arc<NwcManager<StubHandler>>, Arc<RwLock<ConnectionStore>>) {
		manager_with(Arc::new(FailingPersister))
	}

	fn manager_with(
		persister: Arc<dyn ConnectionPersister>,
	) -> (Arc<NwcManager<StubHandler>>, Arc<RwLock<ConnectionStore>>) {
		let mut store = ConnectionStore::new();
		store.set_relays(vec![relay()]);
		let connections = Arc::new(RwLock::new(store));
		let manager = NwcManager::new(
			Arc::new(StubHandler),
			Arc::clone(&connections),
			persister,
		);
		(manager, connections)
	}

	/// A closed local port, so a started service never reaches the network.
	fn relay() -> RelayUrl {
		RelayUrl::parse("ws://127.0.0.1:1").unwrap()
	}

	fn connection(now: chrono::DateTime<chrono::Utc>) -> Connection {
		Connection::generate(
			"app".into(),
			vec![relay()],
			["get_balance".to_string()].into_iter().collect(),
			now,
		).0
	}

	fn now() -> chrono::DateTime<chrono::Utc> {
		chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap()
	}

	/// A connection we failed to write down would be served now and gone after
	/// a restart.
	#[test]
	fn a_connection_that_could_not_be_persisted_is_not_kept() {
		let (manager, connections) = manager();

		manager.add(connection(now())).unwrap_err();

		assert!(connections.read().is_empty(), "the failed add left the connection behind");
	}

	/// A failed revoke has to stay revocable: dropping it from memory makes the
	/// retry report that there was nothing to revoke.
	#[test]
	fn a_revoke_that_could_not_be_persisted_can_be_retried() {
		let (manager, connections) = manager();
		let connection = connection(now());
		let pubkey = connection.client_pubkey.clone();
		connections.write().insert(connection);

		manager.revoke(&pubkey).unwrap_err();

		assert!(
			connections.read().get(&pubkey).is_some(),
			"the failed revoke dropped the connection, so a retry reports nothing to revoke",
		);
		// The retry must reach the persister again rather than short-circuit.
		manager.revoke(&pubkey).unwrap_err();
	}

	/// Relays we failed to write down would be served now and gone after a
	/// restart.
	#[test]
	fn relays_that_could_not_be_persisted_are_not_kept() {
		let (manager, _connections) = manager();

		let other = RelayUrl::parse("ws://127.0.0.1:2").unwrap();
		manager.set_relays(vec![other]).unwrap_err();

		assert_eq!(manager.relays(), vec![relay()], "the failed change was kept");
	}

	/// A service displaced out of the running map could never be stopped again,
	/// since revoke and stop_all both work from it.
	#[tokio::test]
	async fn starting_over_a_running_service_stops_the_one_it_replaces() {
		let (manager, _connections) = manager_with(Arc::new(NoopPersister));
		let connection = connection(now());
		let pubkey = connection.client_pubkey.clone();

		manager.start(&connection);
		let displaced = manager.running.read().get(&pubkey)
			.expect("the first service should be running")
			.shutdown.clone();
		assert!(!displaced.is_cancelled());

		manager.start(&connection);

		assert!(displaced.is_cancelled(), "the replaced service was left running");
		// And the replacement is the one now on record, still running.
		let current = manager.running.read().get(&pubkey)
			.expect("the replacement should be running")
			.shutdown.clone();
		assert!(!current.is_cancelled());

		manager.stop_all();
	}

	/// A relay change has to reach the running services, otherwise they keep
	/// listening on relays that were removed and never join the added ones.
	#[tokio::test]
	async fn changing_relays_restarts_the_running_services() {
		let (manager, connections) = manager_with(Arc::new(NoopPersister));
		let connection = connection(now());
		let pubkey = connection.client_pubkey.clone();
		connections.write().insert(connection);

		manager.start_all();
		let before = manager.running.read().get(&pubkey)
			.expect("the service should be running")
			.shutdown.clone();

		let other = RelayUrl::parse("ws://127.0.0.1:2").unwrap();
		manager.set_relays(vec![other.clone()]).unwrap();

		assert!(before.is_cancelled(), "the service on the old relays was left running");
		assert!(manager.running.read().contains_key(&pubkey), "the service was not restarted");
		assert_eq!(manager.relays(), vec![other]);

		manager.stop_all();
	}

	/// Relays can be set up before the host serves, and doing so must not
	/// bring services up early.
	#[tokio::test]
	async fn changing_relays_before_serving_starts_nothing() {
		let (manager, connections) = manager_with(Arc::new(NoopPersister));
		connections.write().insert(connection(now()));

		manager.set_relays(vec![relay()]).unwrap();

		assert!(manager.running.read().is_empty());
	}

	/// add serves a connection before start_all, so removing the relays then
	/// must stop it.
	#[tokio::test]
	async fn removing_relays_before_serving_stops_added_services() {
		let (manager, _connections) = manager_with(Arc::new(NoopPersister));
		manager.add(connection(now())).unwrap();

		manager.set_relays(Vec::new()).unwrap();

		assert!(manager.running.read().is_empty(), "the service on the removed relays was left running");
	}

	/// With no relays there is nowhere to listen, so nothing is started.
	#[tokio::test]
	async fn no_relays_serves_nothing() {
		let (manager, connections) = manager_with(Arc::new(NoopPersister));
		connections.write().insert(connection(now()));
		manager.set_relays(Vec::new()).unwrap();

		manager.start_all();

		assert!(manager.running.read().is_empty());
		manager.stop_all();
	}
}
