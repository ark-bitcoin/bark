//! The NWC wallet service: relay connection, request loop and info event.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use futures::StreamExt;
use log::{debug, info, trace, warn};
use nostr::event::{Event, EventBuilder, FinalizeEvent, Kind, Tag};
use nostr::filter::Filter;
use nostr::key::{Keys, PublicKey};
use nostr::nips::nip04;
use nostr::nips::nip44::{self, Version};
use nostr::nips::nip47::{ErrorCode, Method, NIP47Error, Request, Response};
use nostr::types::{RelayUrl, Timestamp};
use nostr_sdk::client::{Client, ClientNotification};
use tokio_util::sync::CancellationToken;

use crate::handler::RequestHandler;


/// Replaceable event advertising what the wallet service supports.
const INFO_KIND: Kind = Kind::Custom(13194);
/// Request, client to wallet service.
const REQUEST_KIND: Kind = Kind::Custom(23194);
/// Response, wallet service to client.
const RESPONSE_KIND: Kind = Kind::Custom(23195);

/// Tag naming the encryption scheme a request or response uses.
const TAG_ENCRYPTION: &str = "encryption";
/// Tag after which a request must no longer be acted on.
const TAG_EXPIRATION: &str = "expiration";

/// How long to wait for the relay sockets to come up before serving.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How far back the request subscription reaches.
///
/// This bound is compared against the client's clock, not ours, so it has to
/// absorb the skew between them.
const SUBSCRIBE_GRACE: Duration = Duration::from_secs(120);

/// The `encryption` tag value for NIP-44 v2.
const ENCRYPTION_NIP44: &str = "nip44_v2";
/// The `encryption` tag value for the deprecated NIP-04 scheme.
const ENCRYPTION_NIP04: &str = "nip04";


/// How a request was encrypted, so the response can be encrypted the same way.
///
/// NIP-04 is deprecated but still in use by older clients, and a client that
/// speaks it cannot read a NIP-44 reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encryption {
	Nip44,
	Nip04,
}

impl Encryption {
	/// Pick the scheme from a request's `encryption` tag.
	///
	/// A missing tag means NIP-04: the tag was introduced alongside NIP-44, so
	/// clients that predate it speak the older scheme.
	fn from_event(event: &Event) -> Option<Self> {
		let tag = event.tags.iter()
			.find(|t| t.kind() == TAG_ENCRYPTION)
			.and_then(|t| t.content());

		match tag {
			None => Some(Encryption::Nip04),
			Some(ENCRYPTION_NIP44) => Some(Encryption::Nip44),
			Some(ENCRYPTION_NIP04) => Some(Encryption::Nip04),
			Some(_) => None,
		}
	}

	fn decrypt(&self, keys: &Keys, author: &PublicKey, content: &str) -> anyhow::Result<String> {
		match self {
			Encryption::Nip44 => Ok(nip44::decrypt(keys.secret_key(), author, content)?),
			Encryption::Nip04 => Ok(nip04::decrypt(keys.secret_key(), author, content)?),
		}
	}

	fn encrypt(&self, keys: &Keys, peer: &PublicKey, content: &str) -> anyhow::Result<String> {
		match self {
			Encryption::Nip44 => {
				Ok(nip44::encrypt(keys.secret_key(), peer, content, Version::V2)?)
			},
			Encryption::Nip04 => Ok(nip04::encrypt(keys.secret_key(), peer, content)?),
		}
	}

	fn tag_value(&self) -> &'static str {
		match self {
			Encryption::Nip44 => ENCRYPTION_NIP44,
			Encryption::Nip04 => ENCRYPTION_NIP04,
		}
	}
}


/// A NWC wallet service.
///
/// Holds the service identity, the relay connections and the handler that
/// requests are dispatched to once they are decrypted.
pub struct NwcService<H> {
	keys: Keys,
	relays: Vec<RelayUrl>,
	handler: Arc<H>,
	client: Client,
}

impl<H: RequestHandler> NwcService<H> {
	pub fn new(keys: Keys, relays: Vec<RelayUrl>, handler: Arc<H>) -> Self {
		NwcService { keys, relays, handler, client: Client::new() }
	}

	/// The service pubkey that clients address requests to.
	pub fn public_key(&self) -> PublicKey {
		self.keys.public_key()
	}

	/// Connect to the relays, advertise capabilities and serve requests until
	/// `shutdown` is cancelled.
	pub async fn run(&self, shutdown: CancellationToken) -> anyhow::Result<()> {
		for relay in &self.relays {
			self.client.add_relay(relay.clone()).await
				.with_context(|| format!("failed to add relay {relay}"))?;
		}
		// connect() returns before any socket is up, so waiting here stops the
		// service reporting itself as listening while still unreachable.
		self.client.connect().and_wait(CONNECT_TIMEOUT).await;
		self.report_connections().await;

		self.publish_info_event().await?;

		// Only requests addressed to this service. The lower bound carries a
		// grace window because it is compared against the *client's* clock: a
		// client running a minute behind ours would have every request silently
		// filtered out by the relay, with nothing logged anywhere. Requests are
		// ephemeral events that relays do not store, so a window into the past
		// costs nothing, and a stale request is caught by its expiration tag.
		let since = Timestamp::from_secs(
			Timestamp::now().as_secs().saturating_sub(SUBSCRIBE_GRACE.as_secs()),
		);
		let filter = Filter::new()
			.kind(REQUEST_KIND)
			.pubkey(self.keys.public_key())
			.since(since);
		self.client.subscribe(filter).await
			.context("failed to subscribe to NWC requests")?;

		info!("NWC service listening as {} on {} relay(s)",
			self.keys.public_key(), self.relays.len(),
		);

		let mut notifications = self.client.notifications();
		loop {
			tokio::select! {
				_ = shutdown.cancelled() => break,
				notification = notifications.next() => {
					match notification {
						Some(ClientNotification::Event { event, .. }) => {
							// One bad request must not stop the loop.
							if let Err(e) = self.handle_event(&event).await {
								warn!("Failed to handle NWC request {}: {:#}", event.id, e);
							}
						},
						Some(_) => {},
						None => {
							warn!("NWC notification stream ended, stopping service");
							break;
						},
					}
				},
			}
		}

		self.client.disconnect().await;
		info!("NWC service stopped");
		Ok(())
	}

	/// Publish the kind 13194 info event listing supported methods and
	/// encryption schemes.
	async fn publish_info_event(&self) -> anyhow::Result<()> {
		let methods = self.handler.supported_methods().iter()
			.map(|m| m.to_string())
			.collect::<Vec<_>>()
			.join(" ");

		let event = EventBuilder::new(INFO_KIND, methods.clone())
			.tag(Tag::custom(
				TAG_ENCRYPTION,
				[format!("{ENCRYPTION_NIP44} {ENCRYPTION_NIP04}")],
			))
			.finalize(&self.keys)
			.context("failed to sign NWC info event")?;

		// send_event reports per-relay outcomes in its output rather than
		// failing, so a publish every relay rejected looks like success unless
		// the output is read.
		let output = self.client.send_event(&event).await
			.context("failed to publish NWC info event")?;

		for (relay, error) in &output.failed {
			warn!("Relay {relay} rejected the NWC info event: {error}");
		}
		if output.success.is_empty() {
			warn!("No relay accepted the NWC info event; clients cannot discover \
				this wallet's capabilities");
		} else {
			debug!("Published NWC info event advertising: {}", methods);
		}

		Ok(())
	}

	/// Log which relays are actually connected.
	///
	/// A relay that never connects is otherwise invisible: the service logs
	/// itself as listening and then waits forever for requests that cannot
	/// reach it.
	async fn report_connections(&self) {
		let relays = self.client.relays().await;
		let connected = relays.iter().filter(|(_, r)| r.status().is_connected()).count();

		for (url, relay) in &relays {
			if relay.status().is_connected() {
				debug!("NWC connected to relay {url}");
			} else {
				warn!("NWC relay {url} is not connected ({:?}); requests sent \
					through it will not arrive", relay.status());
			}
		}

		if connected == 0 {
			warn!("NWC is connected to no relays at all; the service will not \
				receive any requests");
		}
	}

	/// Decrypt, dispatch and answer a single request event.
	async fn handle_event(&self, event: &Event) -> anyhow::Result<()> {
		if event.kind != REQUEST_KIND {
			return Ok(());
		}

		// Logged before anything can reject it, so "did the request reach us"
		// is answerable from the log without guessing.
		debug!("Received NWC request {} from {}", event.id, event.pubkey);

		// A request that expired while queued on the relay must not be acted
		// on: the client has already given up and may have paid another way.
		if let Some(expiration) = event.tags.iter()
			.find(|t| t.kind() == TAG_EXPIRATION)
			.and_then(|t| t.content())
			.and_then(|c| c.parse::<u64>().ok())
		{
			if Timestamp::now().as_secs() > expiration {
				debug!("Dropping expired NWC request {}", event.id);
				return Ok(());
			}
		}

		let Some(encryption) = Encryption::from_event(event) else {
			// We cannot encrypt a reply the client can read, so there is
			// nothing useful to send back.
			warn!("Dropping NWC request {} with unsupported encryption", event.id);
			return Ok(());
		};

		let plaintext = encryption.decrypt(&self.keys, &event.pubkey, &event.content)
			.context("failed to decrypt NWC request")?;
		trace!("Decrypted NWC request from {}", event.pubkey);

		let request = Request::from_json(&plaintext)
			.context("failed to parse NWC request")?;
		let method = request.method.clone();

		let result = self.handler.handle(event.pubkey, request).await;
		let response = match result {
			Ok(result) => Response { result_type: method, error: None, result: Some(result) },
			Err(error) => {
				debug!("NWC request from {} failed: {}", event.pubkey, error);
				Response { result_type: method, error: Some(error), result: None }
			},
		};

		self.publish_response(event, encryption, &response).await
	}

	async fn publish_response(
		&self,
		request: &Event,
		encryption: Encryption,
		response: &Response,
	) -> anyhow::Result<()> {
		let content = encryption.encrypt(&self.keys, &request.pubkey, &response.as_json())
			.context("failed to encrypt NWC response")?;

		let event = EventBuilder::new(RESPONSE_KIND, content)
			.tag(Tag::public_key(request.pubkey))
			.tag(Tag::event(request.id))
			.tag(Tag::custom(
				TAG_ENCRYPTION,
				[encryption.tag_value()],
			))
			.finalize(&self.keys)
			.context("failed to sign NWC response")?;

		self.client.send_event(&event).await
			.context("failed to publish NWC response")?;

		Ok(())
	}
}

/// Build the error a handler should return for a method it does not implement.
pub fn not_implemented(method: &Method) -> NIP47Error {
	NIP47Error {
		code: ErrorCode::NotImplemented,
		message: format!("{method} is not supported by bark"),
	}
}


/// End-to-end tests for the service against an in-process relay.
#[cfg(test)]
mod test {
	use std::pin::Pin;
	use std::sync::Arc;
	use std::time::Duration;

	use futures::StreamExt;
	use nostr::event::{EventBuilder, FinalizeEvent, Kind, Tag};
	use nostr::filter::Filter;
	use nostr::key::{Keys, PublicKey};
	use nostr::nips::nip44::{self, Version};
	use nostr::nips::nip47::{
		ErrorCode, GetBalanceResponse, Method, NIP47Error, Request, RequestParams, Response,
		ResponseResult,
	};
	use nostr::types::Timestamp;
	use nostr_sdk::client::Client;
	use nostr_sdk::local_relay::MockRelay;
	use tokio_util::sync::CancellationToken;

	use crate::handler::RequestHandler;
	use super::NwcService;

	// Spelled out rather than taken from the parent module, so that the tests
	// drive the service the way an outside client does. Reusing the service's
	// own constants would make a wrong one agree with itself.
	const REQUEST_KIND: Kind = Kind::Custom(23194);
	const RESPONSE_KIND: Kind = Kind::Custom(23195);

	/// Answers `get_balance` with a fixed amount and rejects everything else, so
	/// the tests exercise the transport rather than a wallet.
	struct StubHandler;

	impl RequestHandler for StubHandler {
		fn handle(
			&self,
			_client: PublicKey,
			request: Request,
		) -> Pin<Box<dyn Future<Output = Result<ResponseResult, NIP47Error>> + Send + '_>> {
			Box::pin(async move {
				match request.params {
					RequestParams::GetBalance => {
						Ok(ResponseResult::GetBalance(GetBalanceResponse { balance: 12_345_000 }))
					},
					_ => Err(NIP47Error {
						code: ErrorCode::NotImplemented,
						message: "stub".into(),
					}),
				}
			})
		}

		fn supported_methods(&self) -> Vec<Method> {
			vec![Method::GetBalance]
		}
	}

	/// Spawn the service against a fresh mock relay, returning the relay url, the
	/// service pubkey and the shutdown token.
	async fn spawn_service() -> (String, PublicKey, CancellationToken) {
		let relay = MockRelay::run().await.unwrap();
		let url = relay.url().await.to_string();

		let keys = Keys::generate();
		let service_key = keys.public_key();
		let shutdown = CancellationToken::new();

		let service = NwcService::new(
			keys,
			vec![nostr::types::RelayUrl::parse(&url).unwrap()],
			Arc::new(StubHandler),
		);

		tokio::spawn({
			let shutdown = shutdown.clone();
			// The relay is dropped when the test ends, so keep it alive here.
			async move {
				let _relay = relay;
				service.run(shutdown).await.unwrap();
			}
		});

		// Give the service time to connect and subscribe before a request is sent.
		tokio::time::sleep(Duration::from_millis(500)).await;

		(url, service_key, shutdown)
	}

	/// Send a NIP-47 request as a client would and wait for the response event.
	async fn round_trip(
		url: &str,
		service_key: PublicKey,
		client_keys: &Keys,
		request: &Request,
	) -> Response {
		let client = Client::new();
		client.add_relay(url).await.unwrap();
		client.connect().await;

		let mut notifications = client.notifications();

		client.subscribe(
			Filter::new().kind(RESPONSE_KIND).pubkey(client_keys.public_key()).since(Timestamp::now()),
		).await.unwrap();

		let content = nip44::encrypt(
			client_keys.secret_key(), &service_key, request.as_json(), Version::V2,
		).unwrap();

		let event = EventBuilder::new(REQUEST_KIND, content)
			.tag(Tag::public_key(service_key))
			.tag(Tag::custom("encryption", ["nip44_v2"]))
			.finalize(client_keys)
			.unwrap();
		client.send_event(&event).await.unwrap();

		let response = tokio::time::timeout(Duration::from_secs(10), async {
			while let Some(notification) = notifications.next().await {
				if let nostr_sdk::client::ClientNotification::Event { event, .. } = notification {
					if event.kind == RESPONSE_KIND {
						let plaintext = nip44::decrypt(
							client_keys.secret_key(), &service_key, &event.content,
						).unwrap();
						return Response::from_json(&plaintext).unwrap();
					}
				}
			}
			panic!("notification stream ended before a response arrived");
		}).await.expect("timed out waiting for the NWC response");

		client.disconnect().await;
		response
	}

	/// The happy path: a request reaches the handler and its result comes back
	/// encrypted to the client.
	#[tokio::test]
	async fn request_reaches_the_handler_and_the_result_comes_back() {
		let (url, service_key, shutdown) = spawn_service().await;
		let client_keys = Keys::generate();

		let request = Request {
			method: Method::GetBalance,
			params: RequestParams::GetBalance,
		};
		let response = round_trip(&url, service_key, &client_keys, &request).await;

		assert_eq!(response.result_type, Method::GetBalance);
		assert!(response.error.is_none(), "unexpected error: {:?}", response.error);
		match response.result {
			Some(ResponseResult::GetBalance(r)) => assert_eq!(r.balance, 12_345_000),
			other => panic!("unexpected result: {:?}", other),
		}

		shutdown.cancel();
	}

	/// A handler error has to come back as a NIP-47 error response rather than
	/// silence, otherwise the client waits until it times out.
	#[tokio::test]
	async fn handler_errors_are_reported_to_the_client() {
		let (url, service_key, shutdown) = spawn_service().await;
		let client_keys = Keys::generate();

		let request = Request {
			method: Method::PayKeysend,
			params: RequestParams::PayKeysend(nostr::nips::nip47::PayKeysendRequest {
				id: None,
				amount: 1000,
				pubkey: Keys::generate().public_key().to_hex(),
				preimage: None,
				tlv_records: Vec::new(),
			}),
		};
		let response = round_trip(&url, service_key, &client_keys, &request).await;

		assert_eq!(response.result_type, Method::PayKeysend);
		assert!(response.result.is_none());
		assert_eq!(response.error.unwrap().code, ErrorCode::NotImplemented);

		shutdown.cancel();
	}

	/// An expired request must be dropped rather than executed. A client that gave
	/// up on a payment may well have paid another way by the time we see it.
	#[tokio::test]
	async fn expired_requests_are_not_executed() {
		let (url, service_key, shutdown) = spawn_service().await;
		let client_keys = Keys::generate();

		let client = Client::new();
		client.add_relay(url.as_str()).await.unwrap();
		client.connect().await;

		let mut notifications = client.notifications();
		client.subscribe(
			Filter::new().kind(RESPONSE_KIND).pubkey(client_keys.public_key()).since(Timestamp::now()),
		).await.unwrap();

		let request = Request { method: Method::GetBalance, params: RequestParams::GetBalance };
		let content = nip44::encrypt(
			client_keys.secret_key(), &service_key, request.as_json(), Version::V2,
		).unwrap();

		let expired = Timestamp::now().as_secs() - 60;
		let event = EventBuilder::new(REQUEST_KIND, content)
			.tag(Tag::public_key(service_key))
			.tag(Tag::custom("encryption", ["nip44_v2"]))
			.tag(Tag::custom("expiration", [expired.to_string()]))
			.finalize(&client_keys)
			.unwrap();
		client.send_event(&event).await.unwrap();

		let got_response = tokio::time::timeout(Duration::from_secs(3), async {
			while let Some(notification) = notifications.next().await {
				if let nostr_sdk::client::ClientNotification::Event { event, .. } = notification {
					if event.kind == RESPONSE_KIND {
						return true;
					}
				}
			}
			false
		}).await;

		assert!(got_response.is_err(), "an expired request must not be answered");

		client.disconnect().await;
		shutdown.cancel();
	}
}
