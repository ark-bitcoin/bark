

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::Context;
use clap;
use log::{debug, info};

use ark::{ArkInfo, Vtxo, VtxoId};
use ark::encode::ProtocolEncoding;
use bark_json::primitives::VtxoInfo;
use server_rpc as rpc;

use crate::util::{https_default_scheme, output_json};
use crate::wallet::open_wallet;

#[derive(clap::Subcommand)]
pub enum DevCommand {
	// ** some general static dev commands

	/// play with vtxos
	#[command(subcommand)]
	Vtxo(VtxoCommand),

	/// inspect the `ArkInfo` of the given server (defaults to wallet server)
	#[command()]
	ArkInfo {
		/// the address of the Ark server to inspect (defaults to wallet server)
		ark_address: String,
	},
}

pub async fn execute_dev_command(
	command: DevCommand,
	datadir: PathBuf,
) -> anyhow::Result<()> {
	match command {
		DevCommand::Vtxo(c) => execute_vtxo_command(&datadir, c).await?,
		DevCommand::ArkInfo { ark_address } => {
			let mut srv = connect_server(ark_address).await
				.context("failed to connect to server")?;
			let res = srv.get_ark_info(rpc::protos::Empty {}).await
				.context("ark_info request failed")?;
			let info = ArkInfo::try_from(res.into_inner())
				.context("invalid ark info from ark server")?;
			output_json(&bark_json::cli::ArkInfo::from(info));
		},
	}
	Ok(())
}

#[derive(clap::Subcommand)]
pub enum VtxoCommand {
	/// decode a serialized VTXO
	#[command()]
	Decode {
		/// VTXO encoded in hex
		vtxo: String,
	},

	/// Drops a vtxo from the database (dangerous)
	#[command()]
	Drop {
		/// You must use this flag to acknowledge the danger of running this command
		#[arg(long = "dangerous")]
		dangerous: bool,
		/// Drop all vtxos
		#[arg(long = "all")]
		all: bool,
		/// Mention a specific vtxo. You can use it multiple times
		#[arg(long= "vtxo")]
		vtxo: Vec<VtxoId>,
	}
}

async fn execute_vtxo_command(datadir: &Path, command: VtxoCommand) -> anyhow::Result<()> {
	match command {
		VtxoCommand::Decode { vtxo } => {
			let vtxo = Vtxo::deserialize_hex(&vtxo).context("invalid vtxo")?;
			// for --verbose print the debug format as well
			debug!("{:#?}", vtxo);
			let info = VtxoInfo::from(vtxo);
			output_json(&info);
		},
		VtxoCommand::Drop { dangerous, all, vtxo} => {
			if !dangerous {
				bail!("You must acknowledge the danger. Run again with --dangerous")
			}

			let (wallet, _onchain) = open_wallet(&datadir).await
				.context("Failed to open wallet")?;

			if all {
				log::info!("Dropping all vtxos");
				wallet.dangerous_drop_all_vtxos().await
					.context("Failed to drop vtxos")?;
			}

			for v in vtxo {
				log::info!("Dropping vtxo {}", v);
				wallet.dangerous_drop_vtxo(v).await
					.context("Failed to drop vtxo")?;
			}
		}
	}
	Ok(())
}

/// Build a tonic endpoint from a server address, configuring timeouts and TLS if required.
///
/// - Supports `http` and `https` URIs. Any other scheme results in an error.
/// - Uses a 10-minute keep-alive and overall request timeout to accommodate long-running RPCs.
/// - When `https` is used, the crate-configured root CAs are enabled and the SNI domain is set.
fn create_server_endpoint(address: &str) -> anyhow::Result<tonic::transport::Endpoint> {
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

/// connect to an Ark server
pub async fn connect_server(
	address: String,
) -> anyhow::Result<rpc::ArkServiceClient<tonic::transport::Channel>> {
	let address = https_default_scheme(address)?;
	let endpoint = create_server_endpoint(&address)?;
	let channel = endpoint.connect().await
		.context("couldn't connect to Ark server")?;
	Ok(rpc::ArkServiceClient::new(channel))
}
