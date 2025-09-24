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
use std::str::FromStr;
use std::time::Duration;

use bitcoin::Network;
use log::{info, warn};

use ark::ArkInfo;

use crate::{protos, ArkServiceClient, ConvertError, RequestExt};


/// The minimum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MIN_PROTOCOL_VERSION: u64 = 1;

/// The maximum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MAX_PROTOCOL_VERSION: u64 = 1;

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
	Handshake(String),
	#[error("version mismatch. Client max is: {client_max}, server min is: {server_min}")]
	ProtocolVersionMismatchClientTooOld { client_max: u64, server_min: u64 },
	#[error("version mismatch. Client min is: {client_min}, server max is: {server_max}")]
	ProtocolVersionMismatchServerTooOld { client_min: u64, server_max: u64 },
	#[error("error getting ark info: {0}")]
	GetArkInfo(#[from] tonic::Status),
	#[error("invalid ark info from ark server: {0}")]
	InvalidArkInfo(#[from] ConvertError),
	#[error("network mismatch. Expected: {expected}, Got: {got}")]
	NetworkMismatch { expected: Network, got: Network },
}

/// A gRPC interceptor that attaches the negotiated protocol version to each request.
///
/// After the handshake determines the mutually supported protocol version, this
/// interceptor injects it into the outgoing request metadata so the server can
/// process calls according to the agreed wire format and semantics.
struct ProtocolVersionInterceptor {
	pver: u64,
}

impl tonic::service::Interceptor for ProtocolVersionInterceptor {
	fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
		req.set_pver(self.pver);
		Ok(req)
	}
}

/// A managed connection to the Ark server.
///
/// This type encapsulates:
/// - `pver`: The negotiated protocol version for the current session.
/// - `info`: The server's [ArkInfo] configuration snapshot retrieved at connection time.
/// - `client`: A ready-to-use gRPC client bound to the same channel used for the handshake.
#[derive(Clone)]
pub struct ServerConnection {
	/// Protocol version used for rpc protocol.
	///
	/// For info on protocol versions, see [server_rpc] module documentation.
	#[allow(unused)]
	pub pver: u64,
	/// Server-side configuration and network parameters returned after connection.
	pub info: ArkInfo,
	/// The gRPC client to call Ark RPCs.
	pub client: ArkServiceClient<tonic::transport::Channel>,
}

impl ServerConnection {
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
		let handshake = handshake_client.handshake(protos::HandshakeRequest {
			bark_version: Some(env!("CARGO_PKG_VERSION").into()),
		}).await.map_err(|e| ConnectError::Handshake(e.to_string()))?.into_inner();


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

		let interceptor = ProtocolVersionInterceptor { pver };
		let mut client = ArkServiceClient::with_interceptor(channel, interceptor);

		let res = client.get_ark_info(protos::Empty {}).await
			.map_err(ConnectError::GetArkInfo)?;
		let info = ArkInfo::try_from(res.into_inner())
			.map_err(ConnectError::InvalidArkInfo)?;
		if network != info.network {
			return Err(ConnectError::NetworkMismatch { expected: network, got: info.network });
		}

		Ok(ServerConnection { pver, info, client: handshake_client })
	}
}
