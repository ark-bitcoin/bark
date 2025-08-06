
use std::cmp;
use std::convert::TryFrom;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bitcoin::Network;
use log::{info, warn};

use ark::ArkInfo;
use server_rpc::{self as rpc, protos, RequestExt};


/// The minimum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MIN_PROTOCOL_VERSION: u64 = 1;

/// The maximum protocol version supported by the client.
///
/// For info on protocol versions, see [server_rpc] module documentation.
pub const MAX_PROTOCOL_VERSION: u64 = 1;


/// A gRPC interceptor that places the protocol version in the metadata header.
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
#[derive(Clone)]
pub struct ServerConnection {
	/// Protocol version used for rpc protocol.
	///
	/// For info on protocol versions, see [server_rpc] module documentation.
	#[allow(unused)]
	pub pver: u64,
	pub info: ArkInfo,
	pub client: rpc::ArkServiceClient<tonic::transport::Channel>,
}

impl ServerConnection {
	fn create_endpoint(address: &str) -> anyhow::Result<tonic::transport::Endpoint> {
		let uri = tonic::transport::Uri::from_str(address)
			.context("failed to parse Ark server as a URI")?;

		let scheme = uri.scheme_str().unwrap_or("");
		if scheme != "http" && scheme != "https" {
			bail!("Ark server scheme must be either http or https. Found: {}", scheme);
		}

		let mut endpoint = tonic::transport::Channel::builder(uri.clone())
			.keep_alive_timeout(Duration::from_secs(600))
			.timeout(Duration::from_secs(600));

		if scheme == "https" {
			info!("Connecting to Ark server using TLS...");
			let uri_auth = uri.clone().into_parts().authority
				.context("Ark server URI is missing an authority part")?;
			let domain = uri_auth.host();

			let tls_config = tonic::transport::ClientTlsConfig::new()
				.with_enabled_roots()
				.domain_name(domain);
			endpoint = endpoint.tls_config(tls_config)?
		} else {
			info!("Connecting to Ark server without TLS...");
		};
		Ok(endpoint)
	}

	/// Try to perform the handshake with the server.
	pub async fn connect(
		address: &str,
		network: Network,
	) -> anyhow::Result<ServerConnection> {
		let endpoint = ServerConnection::create_endpoint(address)?;
		let channel = endpoint.connect().await
			.context("couldn't connect to Ark server")?;

		let mut handshake_client = rpc::ArkServiceClient::new(channel.clone());
		let handshake = handshake_client.handshake(protos::HandshakeRequest {
			bark_version: Some(env!("CARGO_PKG_VERSION").into()),
		}).await.context("handshake request failed")?.into_inner();

		if let Some(ref msg) = handshake.psa {
			warn!("Message from Ark server: \"{}\"", msg);
		}

		if MAX_PROTOCOL_VERSION < handshake.min_protocol_version {
			bail!("protocol version handshake failed: client version too old");
		}
		if MIN_PROTOCOL_VERSION > handshake.max_protocol_version {
			bail!("protocol version handshake failed: server version too old");
		}

		let pver = cmp::min(MAX_PROTOCOL_VERSION, handshake.max_protocol_version);
		assert!((MIN_PROTOCOL_VERSION..=MAX_PROTOCOL_VERSION).contains(&pver));
		assert!((handshake.min_protocol_version..=handshake.max_protocol_version).contains(&pver));

		let interceptor = ProtocolVersionInterceptor { pver };
		let mut client = rpc::ArkServiceClient::with_interceptor(channel, interceptor);

		let res = client.get_ark_info(protos::Empty {}).await
			.context("error getting ark info")?;
		let info = ArkInfo::try_from(res.into_inner())
			.context("invalid ark info from ark server")?;
		if network != info.network {
			bail!("Ark server is for net {} while we are on net {}", info.network, network);
		}

		Ok(ServerConnection { pver, info, client: handshake_client })
	}
}
