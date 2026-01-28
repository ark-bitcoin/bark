//! Client-side Ark server connector.
//!
//! This module provides a managed, version-aware gRPC connection between a
//! Bark client and a paired Ark server. Its responsibilities are:
//! - Negotiating and enforcing a compatible wire protocol version via a
//!   handshake.
//! - Establishing a gRPC channel (optionally with TLS) with sensible timeouts
//!   and keepalives.
//! - Injecting the negotiated protocol version into every RPC call so the
//!   server can route/validate requests correctly.
//! - Fetching and exposing the server's runtime configuration ([ArkInfo]) so
//!   the client can adapt its behavior (e.g., network, round cadence, limits).
//!
//! Overview
//! - Version negotiation: The client first calls the server's handshake RPC,
//!   which returns the supported protocol version range. The client checks its
//!   own supported range ([MIN_PROTOCOL_VERSION]..=[MAX_PROTOCOL_VERSION]) and
//!   picks the highest mutually supported version.
//! - Metadata propagation: After negotiation, all subsequent RPCs carry the
//!   selected protocol version in the request metadata using a gRPC
//!   interceptor.
//! - TLS: If the server URI is HTTPS, a TLS configuration with the configured
//!   crate roots is set up; otherwise the connection proceeds in cleartext.
//! - Server info: Once connected, the client retrieves [ArkInfo] to validate
//!   that the selected Bitcoin [Network] matches the wallet and to learn
//!   server-side parameters that drive client behavior.
//!

use std::cmp;
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bitcoin::Network;
use log::{info, warn};
use tokio::sync::RwLock;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

use ark::ArkInfo;

use crate::{protos, ArkServiceClient, ConvertError, RequestExt};
use crate::mailbox;

/// The minimum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc](crate) module documentation.
pub const MIN_PROTOCOL_VERSION: u64 = 1;

/// The maximum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc](crate) module documentation.
pub const MAX_PROTOCOL_VERSION: u64 = 1;

/// The time to live for the Ark info.
///
/// The Ark info is refreshed every 10 minutes.
pub const ARK_INFO_TTL: u32 = 10 * 60;

#[derive(Debug, thiserror::Error)]
#[error("failed to create gRPC endpoint: {msg}")]
pub enum CreateEndpointError {
	#[error("failed to parse Ark server as a URI")]
	InvalidUri(#[from] http::uri::InvalidUri),
	#[error("Ark server scheme must be either http or https. Found: {0}")]
	InvalidScheme(String),
	#[error("Ark server URI is missing an authority part")]
	MissingAuthority,
	#[error("TLS config error: {0}")]
	TlsConfig(#[from] tonic::transport::Error),
}

#[derive(Debug, thiserror::Error)]
#[error("failed to connect to Ark server: {msg}")]
pub enum ConnectError {
	#[error(transparent)]
	CreateEndpoint(#[from] CreateEndpointError),
	#[error(transparent)]
	Connect(#[from] tonic::transport::Error),
	#[error("handshake request failed: {0}")]
	Handshake(tonic::Status),
	#[error("version mismatch. Client max is: {client_max}, server min is: {server_min}")]
	ProtocolVersionMismatchClientTooOld { client_max: u64, server_min: u64 },
	#[error("version mismatch. Client min is: {client_min}, server max is: {server_max}")]
	ProtocolVersionMismatchServerTooOld { client_min: u64, server_max: u64 },
	#[error("error getting ark info: {0}")]
	GetArkInfo(tonic::Status),
	#[error("invalid ark info from ark server: {0}")]
	InvalidArkInfo(#[from] ConvertError),
	#[error("network mismatch. Expected: {expected}, Got: {got}")]
	NetworkMismatch { expected: Network, got: Network },
	#[error("tokio channel error: {0}")]
	Tokio(#[from] tokio::sync::oneshot::error::RecvError),
}

/// A gRPC interceptor that attaches the negotiated protocol version to each request.
///
/// After the handshake determines the mutually supported protocol version, this
/// interceptor injects it into the outgoing request metadata so the server can
/// process calls according to the agreed wire format and semantics.
#[derive(Clone)]
pub struct ProtocolVersionInterceptor {
	pver: u64,
}

impl tonic::service::Interceptor for ProtocolVersionInterceptor {
	fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
		req.set_pver(self.pver);
		Ok(req)
	}
}

/// A handle to the Ark info.
///
/// This handle is used to wait for the Ark info to be updated, if needed.
pub struct ArkInfoHandle {
	pub info: ArkInfo,
	pub waiter: Option<tokio::sync::oneshot::Receiver<Result<ArkInfo, ConnectError>>>,
}

impl Deref for ArkInfoHandle {
	type Target = ArkInfo;

	fn deref(&self) -> &Self::Target {
		&self.info
	}
}

pub struct ServerInfo {
	/// Protocol version used for rpc protocol.
	///
	/// For info on protocol versions, see [server_rpc](crate) module documentation.
	pub pver: u64,
	/// Server-side configuration and network parameters returned after connection.
	pub info: ArkInfo,
	/// Informations contained in this struct will be considered outdated after this time.
	pub refresh_at: SystemTime,
}

impl ServerInfo {
	/// Compute the time at which the Ark info will be considered outdated.
	fn ttl() -> SystemTime {
		SystemTime::now() + Duration::from_secs(ARK_INFO_TTL as u64)
	}

	pub fn new(pver: u64, info: ArkInfo) -> Self {
		Self { pver, info, refresh_at: Self::ttl() }
	}

	pub fn update(&mut self, info: ArkInfo) {
		self.info = info;
		self.refresh_at = Self::ttl();
	}

	/// Checks if the information contained in this struct is outdated.
	pub fn is_outdated(&self) -> bool {
		SystemTime::now() > self.refresh_at
	}
}

/// A managed connection to the Ark server.
///
/// Note: it is not clonable on purpose, to avoid keeping an outdated connection.
///
/// This type encapsulates:
/// - `pver`: The negotiated protocol version for the current session.
/// - `info`: The server's [ArkInfo] configuration snapshot retrieved at connection time.
/// - `client`: A ready-to-use gRPC client bound to the same channel used for the handshake.
#[derive(Clone)]
pub struct ServerConnection {
	info: Arc<RwLock<ServerInfo>>,
	/// The gRPC client to call Ark RPCs.
	pub client: ArkServiceClient<InterceptedService<Channel, ProtocolVersionInterceptor>>,
	/// The mailbox gRPC client to call mailbox RPCs.
	pub mailbox_client: mailbox::MailboxServiceClient<InterceptedService<Channel, ProtocolVersionInterceptor>>,
}

impl ServerConnection {
	fn handshake_req() -> protos::HandshakeRequest {
		protos::HandshakeRequest {
			bark_version: Some(env!("CARGO_PKG_VERSION").into()),
		}
	}

	/// Build a tonic endpoint from a server address, configuring timeouts and TLS if required.
	///
	/// - Supports `http` and `https` URIs. Any other scheme results in an error.
	/// - Uses a 10-minute keep-alive and overall request timeout to accommodate long-running RPCs.
	/// - When `https` is used, the crate-configured root CAs are enabled and the SNI domain is set.
	fn create_endpoint(address: &str) -> Result<tonic::transport::Endpoint, CreateEndpointError> {
		let uri = tonic::transport::Uri::from_str(address)?;

		let scheme = uri.scheme_str().unwrap_or("");
		if scheme != "http" && scheme != "https" {
			return Err(CreateEndpointError::InvalidScheme(scheme.to_string()));
		}

		let mut endpoint = tonic::transport::Channel::builder(uri.clone())
			.keep_alive_timeout(Duration::from_secs(600))
			.timeout(Duration::from_secs(600));

		if scheme == "https" {
			info!("Connecting to Ark server using TLS...");
			let uri_auth = uri.clone().into_parts().authority
				.ok_or(CreateEndpointError::MissingAuthority)?;
			let domain = uri_auth.host();

			let tls_config = tonic::transport::ClientTlsConfig::new()
				.with_enabled_roots()
				.domain_name(domain);
			endpoint = endpoint.tls_config(tls_config)?;
		} else {
			info!("Connecting to Ark server without TLS...");
		};
		Ok(endpoint)
	}

	/// Establish a connection to an Ark server and perform protocol negotiation.
	///
	/// Steps performed:
	/// 1. Build and connect a gRPC channel to `address` (with TLS for https).
	/// 2. Perform the handshake RPC, sending the Bark client version.
	/// 3. Validate the server's supported protocol range against
	///    [MIN_PROTOCOL_VERSION]..=[MAX_PROTOCOL_VERSION] and select a version.
	/// 4. Create a client with a protocol-version interceptor to tag future calls.
	/// 5. Fetch [ArkInfo] and verify it matches the provided Bitcoin [Network].
	///
	/// Returns a [ServerConnection] with:
	/// - the negotiated protocol version,
	/// - the server's configuration snapshot,
	/// - and a gRPC client bound to the established channel.
	///
	/// Errors if the server cannot be reached, handshake fails, protocol versions
	/// are incompatible, or the server's network does not match `network`.
	pub async fn connect(
		address: &str,
		network: Network,
	) -> Result<ServerConnection, ConnectError> {
		let endpoint = ServerConnection::create_endpoint(address)?;
		let channel = endpoint.connect().await?;

		let mut handshake_client = ArkServiceClient::new(channel.clone());
		let handshake = handshake_client.handshake(Self::handshake_req()).await
			.map_err(ConnectError::Handshake)?.into_inner();

		let pver = check_handshake(handshake)?;

		let interceptor = ProtocolVersionInterceptor { pver };
		let mut client = ArkServiceClient::with_interceptor(channel.clone(), interceptor.clone())
			.max_decoding_message_size(64 * 1024 * 1024); // 64MB limit

		let info = client.ark_info(network).await?;
		info!("Ark info: {:?}", info);

		let mailbox_client = mailbox::MailboxServiceClient::with_interceptor(channel, interceptor)
			.max_decoding_message_size(64 * 1024 * 1024); // 64MB limit

		let info = Arc::new(RwLock::new(ServerInfo::new(pver, info)));
		Ok(ServerConnection {
			info,
			client,
			mailbox_client,
		})
	}

	/// Checks the connection to the Ark server by performing an handshake request.
	pub async fn check_connection(&self) -> Result<(), ConnectError> {
		let mut client = self.client.clone();
		let handshake = client.handshake(Self::handshake_req()).await
			.map_err(ConnectError::Handshake)?.into_inner();
		check_handshake(handshake)?;
		Ok(())
	}

	/// Returns a [ArkInfoHandle]
	///
	/// If the Ark info is outdated, a new request will be sent to
	/// the Ark server to refresh it asynchronously.
	///
	/// The handle also contains a receiver that will be signalled
	/// when the Ark info is successfully refreshed.
	pub async fn ark_info(&self) -> Result<ArkInfo, ConnectError> {
		let mut current = self.info.write().await;

		let new_info = self.client.clone().ark_info(current.info.network).await?;
		if current.is_outdated() {
			current.update(new_info.clone());
			return Ok(new_info);
		}

		Ok(current.info.clone())
	}
}
trait ArkServiceClientExt {
	async fn ark_info(&mut self, network: Network) -> Result<ArkInfo, ConnectError>;
}

impl ArkServiceClientExt for ArkServiceClient<InterceptedService<Channel, ProtocolVersionInterceptor>> {
	async fn ark_info(&mut self, network: Network) -> Result<ArkInfo, ConnectError> {
		let res = self.get_ark_info(protos::Empty {}).await
			.map_err(ConnectError::GetArkInfo)?;
		let info = ArkInfo::try_from(res.into_inner())
			.map_err(ConnectError::InvalidArkInfo)?;
		if network != info.network {
			return Err(ConnectError::NetworkMismatch { expected: network, got: info.network });
		}

		Ok(info)
	}
}

fn check_handshake(handshake: protos::HandshakeResponse) -> Result<u64, ConnectError> {
	if let Some(ref msg) = handshake.psa {
		warn!("Message from Ark server: \"{}\"", msg);
	}

	if MAX_PROTOCOL_VERSION < handshake.min_protocol_version {
		return Err(ConnectError::ProtocolVersionMismatchClientTooOld {
			client_max: MAX_PROTOCOL_VERSION, server_min: handshake.min_protocol_version
		});
	}
	if MIN_PROTOCOL_VERSION > handshake.max_protocol_version {
		return Err(ConnectError::ProtocolVersionMismatchServerTooOld {
			client_min: MIN_PROTOCOL_VERSION, server_max: handshake.max_protocol_version
		});
	}

	let pver = cmp::min(MAX_PROTOCOL_VERSION, handshake.max_protocol_version);
	assert!((MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&pver));
	assert!((handshake.min_protocol_version..=handshake.max_protocol_version).contains(&pver));

	Ok(pver)
}
