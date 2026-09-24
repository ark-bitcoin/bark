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
