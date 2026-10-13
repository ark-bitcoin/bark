//! Connections, and what each of them is allowed to do.
//!
//! A connection URI carries spend authority, so handing one to an app is
//! handing that app the ability to move money.
//!
//! Each connection gets its own keypair. That keeps one app's activity
//! unlinkable from another's, and makes revocation a local delete rather than a
//! rotation of the wallet identity.
//!
//! ```
//! use bark_nwc::{Connection, ConnectionStore};
//! use nostr::nips::nip47::Method;
//! use nostr::types::RelayUrl;
//!
//! let now = chrono::Utc::now();
//! let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];
//! let methods = ["pay_invoice".to_string()].into_iter().collect();
//!
//! // The URI goes to the app; only the connection is kept.
//! let (connection, _uri) = Connection::generate("my app".into(), relays, methods, now);
//! let client = connection.client_pubkey.clone();
//!
//! let mut store = ConnectionStore::new();
//! store.insert(connection);
//!
//! store.authorise(&client, &Method::PayInvoice).unwrap();
//! // A method that was not granted is refused outright.
//! assert!(store.authorise(&client, &Method::GetBalance).is_err());
//! ```

use std::collections::{HashMap, HashSet};

use nostr::key::Keys;
use nostr::nips::nip47::{ErrorCode, Method, NIP47Error, NostrWalletConnectUri};
use nostr::types::RelayUrl;
use serde::{Deserialize, Serialize};


/// Serialised form of a [Method], since [Method] is not a map key we control.
fn method_name(method: &Method) -> String {
	method.to_string()
}


/// A single app's access to the wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
	/// Human-readable name, for the operator's benefit when revoking.
	pub name: String,
	/// The client's pubkey, derived from the secret in the connection URI.
	/// This is the identity every request is authorised against.
	pub client_pubkey: String,
	/// The service keypair for this connection, hex-encoded.
	///
	/// Per-connection rather than wallet-wide, so that two apps cannot be
	/// correlated by the pubkey they talk to.
	pub service_secret: String,
	/// Methods this connection may call. A method absent here is refused even
	/// if the wallet supports it.
	pub allowed_methods: HashSet<String>,
	pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Connection {
	/// Create a new connection, generating both client and service keypairs.
	///
	/// Returns the connection and the URI to hand to the app. The client secret
	/// only exists inside that URI: we keep the pubkey to authorise requests,
	/// never the secret, so a leak of our state cannot impersonate the app.
	pub fn generate(
		name: String,
		relays: Vec<RelayUrl>,
		allowed_methods: HashSet<String>,
		now: chrono::DateTime<chrono::Utc>,
	) -> (Connection, NostrWalletConnectUri) {
		let service = Keys::generate();
		let client = Keys::generate();

		let uri = NostrWalletConnectUri::new(
			service.public_key(),
			relays,
			client.secret_key().clone(),
			None,
		);

		let connection = Connection {
			name: name,
			client_pubkey: client.public_key().to_hex(),
			service_secret: service.secret_key().to_secret_hex(),
			allowed_methods: allowed_methods,
			created_at: now,
		};

		(connection, uri)
	}

	/// The service keypair this connection is served on.
	pub fn service_keys(&self) -> anyhow::Result<Keys> {
		Ok(Keys::parse(&self.service_secret)?)
	}

	/// Whether this connection may call `method`.
	pub fn allows(&self, method: &Method) -> bool {
		self.allowed_methods.contains(&method_name(method))
	}
}


/// Why a request was refused before it reached the wallet.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
	#[error("no connection is registered for this public key")]
	UnknownConnection,
	#[error("this connection is not allowed to call {method}")]
	MethodNotAllowed {
		method: String,
	},
}

impl From<AuthError> for NIP47Error {
	fn from(e: AuthError) -> Self {
		let code = match e {
			AuthError::UnknownConnection => ErrorCode::Unauthorized,
			AuthError::MethodNotAllowed { .. } => ErrorCode::Restricted,
		};
		NIP47Error { code, message: e.to_string() }
	}
}


/// The set of connections a wallet has handed out.
///
/// Persistence lives in bark, so this type only owns the in-memory state and
/// the rules. That keeps the authorisation logic testable without touching a
/// filesystem.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionStore {
	/// Keyed by client pubkey, which is what arrives on every request.
	connections: HashMap<String, Connection>,
}

impl ConnectionStore {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn insert(&mut self, connection: Connection) {
		self.connections.insert(connection.client_pubkey.clone(), connection);
	}

	pub fn remove(&mut self, client_pubkey: &str) -> Option<Connection> {
		self.connections.remove(client_pubkey)
	}

	pub fn get(&self, client_pubkey: &str) -> Option<&Connection> {
		self.connections.get(client_pubkey)
	}

	pub fn iter(&self) -> impl Iterator<Item = &Connection> {
		self.connections.values()
	}

	pub fn is_empty(&self) -> bool {
		self.connections.is_empty()
	}

	/// Check that `client_pubkey` may call `method`.
	pub fn authorise(&self, client_pubkey: &str, method: &Method) -> Result<(), AuthError> {
		let connection = self.get(client_pubkey).ok_or(AuthError::UnknownConnection)?;

		if !connection.allows(method) {
			return Err(AuthError::MethodNotAllowed { method: method_name(method) });
		}

		Ok(())
	}
}


#[cfg(test)]
mod test {
	use super::*;

	fn connection() -> Connection {
		Connection {
			name: "test app".into(),
			client_pubkey: "client".into(),
			service_secret: "secret".into(),
			allowed_methods: [
				method_name(&Method::GetBalance),
				method_name(&Method::PayInvoice),
			].into_iter().collect(),
			created_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
		}
	}

	#[test]
	fn unknown_connections_are_refused() {
		let store = ConnectionStore::new();
		assert_eq!(
			store.authorise("nobody", &Method::GetBalance),
			Err(AuthError::UnknownConnection),
		);
	}

	/// A method the wallet implements is still refused when the connection was
	/// not granted it, which is what makes a read-only connection read-only.
	#[test]
	fn methods_outside_the_allowlist_are_refused() {
		let mut store = ConnectionStore::new();
		store.insert(connection());

		store.authorise("client", &Method::GetBalance).unwrap();
		assert_eq!(
			store.authorise("client", &Method::MakeInvoice),
			Err(AuthError::MethodNotAllowed { method: "make_invoice".into() }),
		);
	}

	/// Revoking a connection has to take effect immediately, since it is the
	/// only way to stop an app that is misbehaving.
	#[test]
	fn removing_a_connection_revokes_access() {
		let mut store = ConnectionStore::new();
		store.insert(connection());
		store.authorise("client", &Method::GetBalance).unwrap();

		store.remove("client").unwrap();
		assert_eq!(
			store.authorise("client", &Method::GetBalance),
			Err(AuthError::UnknownConnection),
		);
	}
}


#[cfg(test)]
mod key_test {
	use super::*;

	/// The pubkey inside the URI must be the one the service listens on.
	///
	/// If these drift the client addresses a key nobody is subscribed to, the
	/// relay accepts the request, and barkd never sees it: a failure with no
	/// error anywhere.
	#[test]
	fn the_uri_names_the_key_the_service_listens_on() {
		let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
		let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

		let (connection, uri) = Connection::generate(
			"app".into(), relays, ["get_balance".to_string()].into_iter().collect(), now,
		);

		let listening_as = connection.service_keys().unwrap().public_key();
		assert_eq!(uri.public_key, listening_as, "URI pubkey must match the serving key");
	}

	/// The client secret handed out must derive the pubkey we authorise against.
	#[test]
	fn the_uri_secret_derives_the_stored_client_pubkey() {
		let now = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
		let relays = vec![RelayUrl::parse("wss://relay.example.com").unwrap()];

		let (connection, uri) = Connection::generate(
			"app".into(), relays, ["get_balance".to_string()].into_iter().collect(), now,
		);

		let derived = Keys::new(uri.secret.clone()).public_key().to_hex();
		assert_eq!(derived, connection.client_pubkey);
	}
}
