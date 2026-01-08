use std::{fmt, fs, io};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, FeeRate};
use bitcoin_ext::BlockDelta;
use cln_rpc::plugins::hold::hold_client::HoldClient;
use config::{Environment, File, Value};
use serde::{Deserialize, Serialize};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use cln_rpc::node_client::NodeClient;

use crate::{forfeits, utils, sweeps, vtxopool};
use crate::secret::Secret;


/// Wraps another config struct but adds an enabled boolean
pub enum OptionalService<T> {
	Enabled(T),
	Disabled,
}

impl<T> OptionalService<T> {
	pub fn enabled(&self) -> Option<&T> {
		match self {
			Self::Enabled(c) => Some(c),
			Self::Disabled => None,
		}
	}

	pub fn enabled_mut(&mut self) -> Option<&mut T> {
		match self {
			Self::Enabled(c) => Some(c),
			Self::Disabled => None,
		}
	}
}

impl<T> From<T> for OptionalService<T> {
	fn from(cfg: T) -> Self {
	    Self::Enabled(cfg)
	}
}

impl<T: Clone> Clone for OptionalService<T> {
	fn clone(&self) -> Self {
	    match self {
			Self::Enabled(c) => Self::Enabled(c.clone()),
			Self::Disabled => Self::Disabled,
		}
	}
}

impl<T: fmt::Debug> fmt::Debug for OptionalService<T> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    match self {
			Self::Enabled(c) => fmt::Debug::fmt(c, f),
			Self::Disabled => write!(f, "Disabled"),
		}
	}
}

impl<T: serde::Serialize> serde::Serialize for OptionalService<T> {
	fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
		#[derive(Serialize)]
	    struct C<T> {
			enabled: bool,
			#[serde(flatten)]
			config: Option<T>,
		}

		let c = match self {
			Self::Enabled(c) => C { enabled: true, config: Some(c) },
			Self::Disabled => C { enabled: false, config: None },
		};

		serde::Serialize::serialize(&c, s)
	}
}

impl<'de, T: serde::Deserialize<'de>> serde::Deserialize<'de> for OptionalService<T> {
	fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
		#[derive(Deserialize)]
	    struct C<T> {
			enabled: bool,
			#[serde(flatten)]
			config: Option<T>,
		}

		let c = C::<T>::deserialize(d)?;
		if c.enabled {
			Ok(Self::Enabled(c.config.ok_or_else(|| serde::de::Error::custom("missing config"))?))
		} else {
			Ok(Self::Disabled)
		}
	}
}


#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bitcoind {
	/// the URL of the bitcoind RPC (mandatory)
	pub url: String,
	/// the path of the cookie file for the bitcoind RPC
	/// It is mandatory to configure exactly one authentication method
	/// This could either be [bitcoind.cookie] or [bitcoind.rpc_user] and [bitcoind.rpc_pass]
	pub cookie: Option<PathBuf>,
	/// the user for the bitcoind RPC
	/// It is mandatory to configure exactly one authentication method
	/// If a [bitcoind.rpc_pass] is provided [bitcoind.rpc_user] must be provided
	pub rpc_user: Option<String>,
	/// the password for the bitcoind RPC
	/// It is mandatory to configure exactly one authentication method
	/// If a [bitcoind.rpc_user] is provided [bitcoind.rpc_pass] must be provided
	pub rpc_pass: Option<Secret<String>>,
}

impl Bitcoind {
	/// Validate the bitcoind config, mostly checking auth
	pub fn validate(&self) -> anyhow::Result<()> {
		let with_user_pass = match (&self.rpc_user, &self.rpc_pass) {
			(Some(_), None) => bail!("Missing configuration bitcoind.rpc_pass. \
				This is required if bitcoind.rpc_user is provided"),
			(None, Some(_)) => bail!("Missing configuration bitcoind.rpc_user. \
				This is required if bitcoind.rpc_pass is provided"),
			(None, None) => false,
			(Some(_),Some(_)) => true,
		};

		if !with_user_pass && self.cookie.is_none() {
			bail!("Configuring authentication to bitcoind is mandatory. \
				Specify either bitcoind.cookie or (bitcoind.rpc_user and bitcoind.rpc_pass).")
		} else if with_user_pass && self.cookie.is_some() {
			bail!("Invalid configuration for authentication to bitcoind. Use either \
				bitcoind.cookie or (bitcoind.rpc_user and bitcoind.rpc_pass) but not both.")
		}

		Ok(())
	}

	pub fn auth(&self) -> bitcoin_ext::rpc::Auth {
		match (&self.rpc_user, &self.rpc_pass) {
			(Some(user), Some(pass)) => bitcoin_ext::rpc::Auth::UserPass(
				user.into(), pass.leak_ref().into(),
			),
			(Some(_), None) => panic!("Missing configuration for bitcoind.rpc_pass."),
			(None, Some(_)) => panic!("Missing configuration for bitcoind.rpc_user."),
			(None, None) => {
				let bitcoind_cookie_file = self.cookie.as_ref()
					.expect("The bitcoind.cookie must be set if username and password aren't provided");

				bitcoin_ext::rpc::Auth::CookieFile(bitcoind_cookie_file.into())
			}
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rpc {
	/// The socket to bind to for the public Ark gRPC.
	pub public_address: SocketAddr,
	/// The socket to bind to for the private admin gRPC.
	pub admin_address: Option<SocketAddr>,
	/// The socket to bind to for the integrations gRPC.
	pub integration_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HodlInvoiceClnPlugin {
	#[serde(with = "utils::serde::string")]
	pub uri: tonic::transport::Uri,
	pub server_cert_path: PathBuf,
	pub client_cert_path: PathBuf,
	pub client_key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lightningd {
	#[serde(with = "utils::serde::string")]
	pub uri: tonic::transport::Uri,
	/// Lowest number has the highest priority.
	pub priority: u8,
	pub server_cert_path: PathBuf,
	pub client_cert_path: PathBuf,
	pub client_key_path: PathBuf,
	pub hold_invoice: Option<HodlInvoiceClnPlugin>,
}

impl Lightningd {
	/// Create a gRPC client to the cln node's main gRPC endpoint.
	pub async fn build_grpc_client(&self) -> anyhow::Result<NodeClient<Channel>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		let ca_pem = fs::read_to_string(&self.server_cert_path)
			.context("failed to read server cert file")?;
		let id_pem = fs::read_to_string(&self.client_cert_path)
			.context("failed to read client cert file")?;
		let id_key = fs::read_to_string(&self.client_key_path)
			.context("failed to read client key file")?;

		let channel = Channel::builder(self.uri.clone())
			.tls_config(ClientTlsConfig::new()
				.ca_certificate(Certificate::from_pem(ca_pem))
				.identity(Identity::from_pem(&id_pem, &id_key))
			)?
			.connect()
			.await?;

		Ok(NodeClient::new(channel))
	}

	pub async fn build_hold_client(&self) ->  anyhow::Result<Option<HoldClient<tonic::transport::Channel>>> {
		// Client doesn't support grpc over http
		// We need to use https using m-TLS authentication
		if let Some(hold_config) = &self.hold_invoice {
			// Client doesn't support grpc over http
			// We need to use https using m-TLS authentication
			let ca_pem = fs::read_to_string(&hold_config.server_cert_path)?;
			let id_pem = fs::read_to_string(&hold_config.client_cert_path)?;
			let id_key = fs::read_to_string(&hold_config.client_key_path)?;

			let channel = Channel::builder(hold_config.uri.clone().into())
				.tls_config(ClientTlsConfig::new()
					.ca_certificate(Certificate::from_pem(ca_pem))
					.identity(Identity::from_pem(&id_pem, &id_key))
					)?
				.connect()
				.await?;

			Ok(Some(HoldClient::new(channel)))
		} else {
			Ok(None)
		}
	}
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Postgres {
	pub host: String,
	pub port: u16,
	pub name: String,
	pub user: Option<String>,
	pub password: Option<Secret<String>>,
	pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
	pub data_dir: PathBuf,
	pub network: bitcoin::Network,
	/// The number of blocks after which a VTXO expires, by default 6*24*30 so that
	/// a VTXO can live for up to 30 days.
	pub vtxo_lifetime: BlockDelta,
	pub vtxo_exit_delta: BlockDelta,

	/// Maximum value any vtxo can have.
	#[serde(default, with = "utils::serde::string::opt")]
	pub max_vtxo_amount: Option<Amount>,
	/// Minimum amount required for board transactions.
	#[serde(with = "utils::serde::string")]
	pub min_board_amount: Amount,
	/// Maximum number of OOR transition after VTXO tree leaf
	pub max_arkoor_depth: u16,
	/// Number of confirmations needed for board vtxos to be spend in rounds.
	pub required_board_confirmations: usize,
	/// Number of confirmations untrusted inputs of the round tx need to have.
	pub round_tx_untrusted_input_confirmations: usize,

	#[serde(with = "utils::serde::duration")]
	pub round_interval: Duration,
	#[serde(with = "utils::serde::duration")]
	pub round_submit_time: Duration,
	#[serde(with = "utils::serde::duration")]
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
	/// The duration after which to drop forfeit nonces
	#[serde(with = "utils::serde::duration")]
	pub round_forfeit_nonces_timeout: Duration,
	#[serde(with = "utils::serde::fee_rate")]
	pub round_tx_feerate: FeeRate,

	/// Whether or not to add full error information to RPC internal errors.
	pub rpc_rich_errors: bool,

	/// The interval at which the txindex checks tx statuses.
	#[serde(with = "utils::serde::duration")]
	pub txindex_check_interval: Duration,

	/// The interval at which the SyncManager polls for new blocks.
	#[serde(with = "utils::serde::duration")]
	pub sync_manager_block_poll_interval: Duration,

	/// A message that can be used by the operator to make
	/// announcements to all cliens.
	pub handshake_psa: Option<String>,

	pub otel_collector_endpoint: Option<String>,
	/// <= 0 -> Tracing always disabled,
	/// 0.5 -> Tracing enabled 50% of the time, and
	/// \>= 1 -> Tracing always active.
	pub otel_tracing_sampler: Option<f64>,
	pub otel_deployment_name: String,

	/// Config for the VtxoSweeper process.
	pub vtxo_sweeper: OptionalService<sweeps::Config>,

	/// Config for the ForfeitWatcher process.
	pub forfeit_watcher: OptionalService<forfeits::Config>,
	#[serde(with = "utils::serde::string")]
	pub forfeit_watcher_min_balance: Amount,

	/// Config for the VtxoPool process
	pub vtxopool: vtxopool::Config,

	// The interval used to rebroadcast transactions
	#[serde(with = "utils::serde::duration")]
	pub transaction_rebroadcast_interval: Duration,

	pub rpc: Rpc,
	pub postgres: Postgres,

	pub bitcoind: Bitcoind,

	#[serde(default)]
	pub cln_array: Vec<Lightningd>,
	#[serde(with = "utils::serde::duration")]
	pub cln_reconnect_interval: Duration,
	#[serde(with = "utils::serde::duration")]
	pub invoice_check_interval: Duration,
	/// The time for which not to manually recheck invoice state.
	#[serde(with = "utils::serde::duration")]
	pub invoice_recheck_delay: Duration,
	#[serde(with = "utils::serde::duration")]
	pub invoice_check_base_delay: Duration,
	#[serde(with = "utils::serde::duration")]
	pub invoice_check_max_delay: Duration,
	#[serde(with = "utils::serde::duration")]
	pub invoice_poll_interval: Duration,

	/// The number of blocks to keep between Lightning and Ark HTLCs expiries.
	///
	/// Default is 6
	pub htlc_expiry_delta: BlockDelta,
	/// The number of blocks after which an HTLC-send VTXO expires once granted.
	/// When granting an HTLC-send VTXO, the Server doesn't know the lightning
	/// route yet, so it needs this config to be sufficiently high to account
	/// for the worst routing scenario.
	///
	/// Default is `min_final_cltv_expiry_delta + n_hops * cltv_expiry_delta`
	/// where _n_hops_ is an upper bound on the expected number of hops a lightning
	/// route usually takes and other vars are lightning defaults: _18 + 6*40 = 258_
	///
	/// Note: it is added to [Config::htlc_expiry_delta] to provide `maxdelay` in
	/// xpay call.
	pub htlc_send_expiry_delta: BlockDelta,
	/// Maximum CLTV delta server will allow clients to request an
	/// invoice generation with.
	///
	/// It should be much higher than the sum of:
	/// - `vtxo_exit_delta` (144) + `htlc_expiry_delta` (40) +
	/// `vtxo_exit_margin` (12) + `htlc_recv_claim_delta` (18)
	///
	/// Note: it is added to [Config::htlc_expiry_delta]
	/// to set the actual invoice's min final cltv expiry delta.
	///
	/// Default is 250
	pub max_user_invoice_cltv_delta: BlockDelta,
	/// The duration after which a generated invoice will expire.
	#[serde(with = "utils::serde::duration")]
	pub invoice_expiry: Duration,
	/// The duration for which the server will hold inbound HTLC(s) while
	/// waiting for a user to claim a lightning receive.
	/// After this timeout the server will fail the HTLC(s) back to the sender.
	#[serde(with = "utils::serde::duration")]
	pub receive_htlc_forward_timeout: Duration,

	/// Indicates whether the Ark server requires clients to either
	/// provide a VTXO ownership proof, or a lightning receive token
	/// when preparing a lightning claim.
	pub ln_receive_anti_dos_required: bool,
}

impl Config {
	fn load_with_custom_env(
		config_file: impl AsRef<Path>,
		#[cfg(test)]
		custom_env: Option<std::collections::HashMap<String, String>>,
	) -> anyhow::Result<Self> {
		// We'll add two layers of config:
		// - the config file passed in this function, if any
		// - environment variables (prefixed with `BARK_SERVER_`)

		let mut builder = config::Config::builder()
			.add_source(File::from(config_file.as_ref()));

		let env = Environment::with_prefix("BARK_SERVER")
			.separator("__");
		#[cfg(test)]
		let env = env.source(custom_env);
		builder = builder.add_source(env);

		// // because the config crate doesn't deal well with empty lists,
		// // we have to manually add all lists that are empty
		builder = builder.set_default("vtxopool.vtxo_targets", Vec::<Value>::new()).unwrap();

		let cln_array = {
			let env_cfg = builder.clone().build().context("error building config")?;
			if let Ok(raw) = env_cfg.get_string("cln_array") {
				// if the environment variable is set, we have to clean up the
				// actual builder so that it doesn't fail on parsing the value regularly
				builder = builder.set_override("cln_array", Vec::<Value>::new()).unwrap();
				serde_json::from_str::<Vec<Lightningd>>(&raw)
					.context("invalid cln_array env var")?
			} else {
				Vec::new()
			}
		};

		let raw_cfg = builder.build().context("error building config")?;
		let mut cfg = raw_cfg.try_deserialize::<Config>().context("error parsing config")?;
		// merge the json parsed cln_array
		cfg.cln_array.extend(cln_array);

		Ok(cfg)
	}

	pub fn load(config_file: impl AsRef<Path>) -> anyhow::Result<Self> {
		Self::load_with_custom_env(config_file, #[cfg(test)] None)
	}

	/// Verifies if the specified configuration is valid
	///
	/// It also checks if all required configurations are available
	pub fn validate(&self) -> anyhow::Result<()> {
		self.bitcoind.validate()?;
		Ok(())
	}

	/// Write the config into the writer.
	pub fn write_into(&self, writer: &mut dyn io::Write) -> anyhow::Result<()> {
		let s = toml::to_string_pretty(self).expect("config serialization error");
		writer.write_all(&s.as_bytes()).context("error writing config to writer")?;
		Ok(())
	}
}

pub mod watchman {
	use bitcoin::{address::NetworkUnchecked, Address};

	use super::*;

	#[derive(Debug, Clone, Deserialize, Serialize)]
	pub struct Config {
		pub data_dir: PathBuf,
		pub network: bitcoin::Network,

		/// The interval at which the txindex checks tx statuses.
		#[serde(with = "utils::serde::duration")]
		pub txindex_check_interval: Duration,

		/// The interval at which the SyncManager polls for new blocks.
		#[serde(with = "utils::serde::duration")]
		pub sync_manager_block_poll_interval: Duration,

		pub otel_collector_endpoint: Option<String>,
		/// <=0 -> Tracing always disabled,
		/// 0.5 -> Tracing enabled 50% of the time, and
		/// >=1 -> Tracing always active.
		pub otel_tracing_sampler: Option<f64>,
		pub otel_deployment_name: String,

		/// Config for the VtxoSweeper process.
		pub vtxo_sweeper: sweeps::Config,
		/// Config for the ForfeitWatcher process.
		pub forfeit_watcher: forfeits::Config,

		// The interval used to rebroadcast transactions
		#[serde(with = "utils::serde::duration")]
		pub transaction_rebroadcast_interval: Duration,

		pub postgres: Postgres,

		pub bitcoind: Bitcoind,

		pub sweep_address: Option<Address<NetworkUnchecked>>, // no default
	}

	impl Config {
		fn load_with_custom_env(
			config_file: impl AsRef<Path>,
			#[cfg(test)]
			custom_env: Option<std::collections::HashMap<String, String>>,
		) -> anyhow::Result<Self> {
			// We'll add two layers of config:
			// - the config file passed in this function, if any
			// - environment variables (prefixed with `WATCHMAND__`)

			let mut builder = config::Config::builder()
				.add_source(File::from(config_file.as_ref()));

			let env = Environment::with_prefix("WATCHMAND")
				.separator("__");
			#[cfg(test)]
			let env = env.source(custom_env);
			builder = builder.add_source(env);

			let raw_cfg = builder.build().context("error building config")?;
			let cfg = raw_cfg.try_deserialize::<Config>().context("error parsing config")?;

			Ok(cfg)
		}

		pub fn load(config_file: impl AsRef<Path>) -> anyhow::Result<Self> {
			Self::load_with_custom_env(config_file, #[cfg(test)] None)
		}

		/// Verifies if the specified configuration is valid
		///
		/// It also checks if all required configurations are available
		pub fn validate(&self) -> anyhow::Result<()> {
			self.bitcoind.validate()?;
			Ok(())
		}

		/// Write the config into the writer.
		pub fn write_into(&self, writer: &mut dyn io::Write) -> anyhow::Result<()> {
			let s = toml::to_string_pretty(self).expect("config serialization error");
			writer.write_all(&s.as_bytes()).context("error writing config to writer")?;
			Ok(())
		}
	}
}

#[cfg(test)]
mod test {
	use std::collections::HashMap;
	use std::str::FromStr;
	use tonic::transport::Uri;
	use super::*;

	const DEFAULT_CAPTAIND_CONFIG_PATH: &str =
		concat!(env!("CARGO_MANIFEST_DIR"), "/captaind.default.toml");
	const DEFAULT_WATCHMAND_CONFIG_PATH: &str =
		concat!(env!("CARGO_MANIFEST_DIR"), "/watchmand.default.toml");

	#[test]
	fn parse_validate_default_captaind_config_file() {
		let mut cfg = Config::load(DEFAULT_CAPTAIND_CONFIG_PATH)
			.expect("error loading config");

		// some configs are mandatory but can't be set in defaults
		cfg.bitcoind.cookie = Some(".cookie".into());

		cfg.validate().expect("error validating default config");
	}

	#[test]
	fn parse_validate_default_watchmand_config_file() {
		let mut cfg = watchman::Config::load(DEFAULT_WATCHMAND_CONFIG_PATH)
			.expect("error loading config");

		// some configs are mandatory but can't be set in defaults
		cfg.bitcoind.cookie = Some(".cookie".into());

		cfg.validate().expect("error validating default config");
	}

	#[test]
	fn validate_bitcoind_config() {
		let default = DEFAULT_CAPTAIND_CONFIG_PATH;
		let bitcoind_url = String::from("http://belson.labs:13444");
		let bitcoind_cookie = Some(PathBuf::from("/not/hot/dog/but/cookie"));
		let bitcoind_rpc_user = Some(String::from("erlich"));
		let bitcoind_rpc_pass = Some(Secret::new(String::from("belson")));

		let mut cfg = Config::load(default).unwrap();
		cfg.bitcoind.url = bitcoind_url.clone();
		cfg.bitcoind.cookie = bitcoind_cookie.clone();
		cfg.validate().expect("This config should be valid");

		let mut cfg = Config::load(default).unwrap();
		cfg.bitcoind.url = bitcoind_url.clone();
		cfg.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		cfg.bitcoind.rpc_pass = bitcoind_rpc_pass.clone();
		cfg.validate().expect("This config should be valid");

		let mut cfg = Config::load(default).unwrap();
		cfg.bitcoind.url = bitcoind_url.clone();
		cfg.validate().expect_err("Invalid because auth info is missing");

		let mut cfg = Config::load(default).unwrap();
		cfg.bitcoind.url = bitcoind_url.clone();
		cfg.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		cfg.validate().expect_err("Invalid because pass is missing");

		let mut cfg = Config::load(default).unwrap();
		cfg.bitcoind.url = bitcoind_url.clone();
		cfg.bitcoind.cookie = bitcoind_cookie.clone();
		cfg.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		cfg.bitcoind.rpc_pass = bitcoind_rpc_pass.clone();
		cfg.validate().expect_err("Invalid. Either cookie or pass but not both");
	}

	#[test]
	fn init_accepts_full_cln_config() {
		let bitcoind_cookie = Some(PathBuf::from("/not/hot/dog/but/cookie"));
		let uri = "http://belson.labs:13444".to_string();
		let server_cert_path = "/hooli/http_public/certs/server.crt".to_string();
		let client_cert_path = "/hooli/http_public/certs/client.crt".to_string();
		let client_key_path = "/hooli/http_public/certs/client.key".to_string();

		let mut cfg = Config::load(DEFAULT_CAPTAIND_CONFIG_PATH).unwrap();

		let cln = Lightningd {
			uri: Uri::from_str(uri.clone().as_str()).unwrap(),
			priority: 1,
			server_cert_path: PathBuf::from(server_cert_path.clone()),
			client_cert_path: PathBuf::from(client_cert_path.clone()),
			client_key_path: PathBuf::from(client_key_path.clone()),
			hold_invoice: None,
		};
		let mut cln_array = Vec::new();
		cln_array.push(cln);

		cfg.bitcoind.cookie = bitcoind_cookie.clone();
		cfg.cln_array = cln_array;

		cfg.validate().expect("invalid configuration");

		let lncfg = cfg.cln_array.get(0).unwrap();
		assert_eq!(lncfg.uri, Uri::from_str(uri.clone().as_str()).unwrap());
		assert_eq!(lncfg.server_cert_path, PathBuf::from(server_cert_path));
		assert_eq!(lncfg.client_cert_path, PathBuf::from(client_cert_path));
		assert_eq!(lncfg.client_key_path, PathBuf::from(client_key_path));
	}

	// ignoring this test because concurrency with environment variables is causing problems.
	#[test]
	fn cln_config_from_env_vars() {
		let uri = "http://belson.labs:12345";
		let server_cert_path = "/hooli/http_public/certs/server.crt";
		let client_cert_path = "/hooli/http_public/certs/client.crt";
		let client_key_path = "/hooli/http_public/certs/client.key";

		let env = [
			("BARK_SERVER__VTXO_LIFETIME", "42"),
			("BARK_SERVER__BITCOIND__COOKIE", "/not/hot/dog/but/cookie"),
			("BARK_SERVER__CLN_ARRAY", r#"[{
				"uri": "http://belson.labs:12345",
				"priority": 1,
				"server_cert_path": "/hooli/http_public/certs/server.crt",
				"client_cert_path": "/hooli/http_public/certs/client.crt",
				"client_key_path": "/hooli/http_public/certs/client.key"
			}]"#),
		].into_iter().map(|(k, v)| (k.into(), v.into())).collect::<HashMap<String, String>>();

		let cfg = Config::load_with_custom_env(DEFAULT_CAPTAIND_CONFIG_PATH, Some(env)).unwrap();
		cfg.validate().expect("invalid configuration");

		assert_eq!(cfg.vtxo_lifetime, 42);
		assert_eq!(cfg.bitcoind.cookie, Some("/not/hot/dog/but/cookie".into()));
		let lncfg = cfg.cln_array.get(0).unwrap();
		assert_eq!(lncfg.uri, Uri::from_str(uri).unwrap());
		assert_eq!(lncfg.server_cert_path, PathBuf::from(server_cert_path));
		assert_eq!(lncfg.client_cert_path, PathBuf::from(client_cert_path));
		assert_eq!(lncfg.client_key_path, PathBuf::from(client_key_path));
	}

	#[test]
	fn test_optional_service() {
		#[derive(Serialize, Deserialize)]
		struct S {
			var: usize,
		}
		#[derive(Serialize, Deserialize)]
		struct C {
			optional: OptionalService<S>,
		}

		let enabled = "[optional]\nenabled = true\nvar = 5";
		let enabled = toml::from_str::<C>(enabled).unwrap();
		assert_eq!(enabled.optional.enabled().unwrap().var, 5);

		let disabled = "[optional]\nenabled = false";
		let disabled = toml::from_str::<C>(disabled).unwrap();
		assert!(disabled.optional.enabled().is_none());
	}
}
