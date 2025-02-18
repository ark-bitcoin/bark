
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use bitcoin::{Amount, FeeRate};
use config::{Environment, File};
use serde::Deserialize;

use crate::serde_util;

#[derive(Debug, Clone, Deserialize, Serialize)]
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
	pub rpc_pass: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rpc {
	/// The socket to bind to for the public Ark gRPC.
	pub public_address: SocketAddr,
	/// The socket to bind to for the private admin gRPC.
	pub admin_address: Option<SocketAddr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Lightningd {
	#[serde(with = "serde_util::uri")]
	pub uri: tonic::transport::Uri,
	pub server_cert_path: PathBuf,
	pub client_cert_path: PathBuf,
	pub client_key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
	pub data_dir: PathBuf,
	pub network: bitcoin::Network,
	pub vtxo_expiry_delta: u16,
	pub vtxo_exit_delta: u16,
	pub htlc_delta: u16,
	pub htlc_expiry_delta: u16,
	#[serde(with = "serde_util::duration")]
	pub round_interval: Duration,
	#[serde(with = "serde_util::duration")]
	pub round_submit_time: Duration,
	#[serde(with = "serde_util::duration")]
	pub round_sign_time: Duration,
	pub nb_round_nonces: usize,
	#[serde(with = "serde_util::fee_rate")]
	pub round_tx_feerate: FeeRate,
	#[serde(with = "serde_util::fee_rate")]
	pub sweep_tx_fallback_feerate: FeeRate,
	#[serde(with = "serde_util::duration")]
	pub round_sweep_interval: Duration,
	/// Number of confirmations needed for onboard vtxos to be spend in rounds.
	pub round_onboard_confirmations: usize,
	#[serde(with = "bitcoin::amount::serde::as_sat::opt")]
	pub max_onboard_value: Option<Amount>,
	/// Don't make sweep txs for amounts lower than this amount.
	pub sweep_threshold: Amount,
	pub otel_collector_endpoint: Option<String>,

	pub rpc: Rpc,

	pub bitcoind: Bitcoind,

	#[serde(skip_serializing_if = "Option::is_none")]
	pub lightningd: Option<Lightningd>,
}

impl Config {
	pub fn load(config_file: Option<&Path>) -> anyhow::Result<Self> {
		let default = config::Config::try_from(&Self::default())
			.expect("default config failed to deconstruct");

		// We'll add three layers of config:
		// - the defaults defined in Config's Default impl
		// - the config file passed in this function, if any
		// - environment variables (prefixed with `ASPD_`)

		let mut builder = config::Config::builder()
			.add_source(default);
		if let Some(file) = config_file {
			builder = builder.add_source(File::from(file));
		}
		builder = builder.add_source(Environment::with_prefix("ASPD").separator("_"));

		let cfg = builder.build().context("error building config")?;
		Ok(cfg.try_deserialize().context("error parsing config")?)
	}

	/// Verifies if the specified configuration is valid
	///
	/// It also checks if all required configurations are available
	pub fn validate(&self) -> anyhow::Result<()> {
		let with_user_pass = match (&self.bitcoind.rpc_user, &self.bitcoind.rpc_pass) {
			(Some(_), None) => bail!("Missing configuration bitcoind.rpc_pass. \
				This is required if bitcoind.rpc_user is provided"),
			(None, Some(_)) => bail!("Missing configuration bitcoind.rpc_user. \
				This is required if bitcoind.rpc_pass is provided"),
			(None, None) => false,
			(Some(_),Some(_)) => true,
		};

		if !with_user_pass && self.bitcoind.cookie.is_none() {
			bail!("Configuring authentication to bitcoind is mandatory. \
				Specify either bitcoind.cookie or (bitcoind.rpc_user and bitcoind.rpc_pass).")
		} else if with_user_pass && self.bitcoind.cookie.is_some() {
			bail!("Invalid configuration for authentication to bitcoind. Use either \
				bitcoind.cookie or (bitcoind.rpc_user and bitcoind.rpc_pass) but not both.")
		}

		Ok(())
	}

	pub fn bitcoind_auth(&self) -> bdk_bitcoind_rpc::bitcoincore_rpc::Auth {
		match (&self.bitcoind.rpc_user, &self.bitcoind.rpc_pass) {
			(Some(user), Some(pass)) => bdk_bitcoind_rpc::bitcoincore_rpc::Auth::UserPass(
				user.into(), pass.into(),
			),
			(Some(_), None) => panic!("Missing configuration for bitcoind.rpc_pass."),
			(None, Some(_)) => panic!("Missing configuration for bitcoind.rpc_user."),
			(None, None) => {
				let bitcoind_cookie_file = self.bitcoind.cookie.as_ref()
					.expect("The bitcoind.cookie must be set if username and password aren't provided");

				bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(bitcoind_cookie_file.into())
			}
		}
	}

	pub fn write_to_file(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
		let path = path.as_ref();
		let s = toml::to_string_pretty(self).expect("config serialization error");
		std::fs::write(path, &s)
			.with_context(|| format!("error writing config to {}", path.display()))?;
		Ok(())
	}
}

impl Default for Config {
	fn default() -> Self {
		Config {
			data_dir: "./aspd".into(),
			network: bitcoin::Network::Regtest,
			vtxo_expiry_delta: 24 * 6,
			vtxo_exit_delta: 2 * 6,
			htlc_delta: 6,
			htlc_expiry_delta: 6,
			round_interval: Duration::from_secs(10),
			round_submit_time: Duration::from_millis(2000),
			round_sign_time: Duration::from_millis(2000),
			nb_round_nonces: 64,
			round_tx_feerate: FeeRate::from_sat_per_vb(10).unwrap(),
			sweep_tx_fallback_feerate: FeeRate::from_sat_per_vb(10).unwrap(),
			round_sweep_interval: Duration::from_secs(60 * 60),
			round_onboard_confirmations: 12,
			max_onboard_value: None,
			sweep_threshold: Amount::from_sat(1_000_000),
			otel_collector_endpoint: None,
			rpc: Rpc {
				public_address: "127.0.0.1:3535".parse().unwrap(),
				admin_address: Some("127.0.0.1:3536".parse().unwrap()),
			},
			bitcoind: Bitcoind {
				url: "http://127.0.0.1:18443".into(),
				cookie: None,
				rpc_user: None,
				rpc_pass: None,
			},
			lightningd : None,
		}
	}
}

#[cfg(test)]
mod test {
	use std::env;
	use std::str::FromStr;
	use tonic::transport::Uri;
	use super::*;

	#[test]
	fn validate_bitcoind_config() {
		let bitcoind_url = String::from("http://belson.labs:13444");
		let bitcoind_cookie = Some(PathBuf::from("/not/hot/dog/but/cookie"));
		let bitcoind_rpc_user = Some(String::from("erlich"));
		let bitcoind_rpc_pass = Some(String::from("belson"));

		let mut configurations = Config::load(None).unwrap();
		configurations.bitcoind.url = bitcoind_url.clone();
		configurations.bitcoind.cookie = bitcoind_cookie.clone();
		configurations.validate().expect("This config should be valid");

		let mut configurations = Config::load(None).unwrap();
		configurations.bitcoind.url = bitcoind_url.clone();
		configurations.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		configurations.bitcoind.rpc_pass = bitcoind_rpc_pass.clone();
		configurations.validate().expect("This config should be valid");

		let mut configurations = Config::load(None).unwrap();
		configurations.bitcoind.url = bitcoind_url.clone();
		configurations.validate().expect_err("Invalid because auth info is missing");

		let mut configurations = Config::load(None).unwrap();
		configurations.bitcoind.url = bitcoind_url.clone();
		configurations.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		configurations.validate().expect_err("Invalid because pass is missing");

		let mut configurations = Config::load(None).unwrap();
		configurations.bitcoind.url = bitcoind_url.clone();
		configurations.bitcoind.cookie = bitcoind_cookie.clone();
		configurations.bitcoind.rpc_user = bitcoind_rpc_user.clone();
		configurations.bitcoind.rpc_pass = bitcoind_rpc_pass.clone();
		configurations.validate().expect_err("Invalid. Either cookie or pass but not both");
	}

	#[test]
	fn init_accepts_full_cln_config() {
		let bitcoind_cookie = Some(PathBuf::from("/not/hot/dog/but/cookie"));
		let uri = "http://belson.labs:13444".to_string();
		let server_cert_path = "/hooli/http_public/certs/server.crt".to_string();
		let client_cert_path = "/hooli/http_public/certs/client.crt".to_string();
		let client_key_path = "/hooli/http_public/certs/client.key".to_string();

		let mut configurations = Config::load(None).unwrap();

		let cln = Lightningd {
			uri: Uri::from_str(uri.clone().as_str()).unwrap(),
			server_cert_path: PathBuf::from(server_cert_path.clone()),
			client_cert_path: PathBuf::from(client_cert_path.clone()),
			client_key_path: PathBuf::from(client_key_path.clone()),
		};

		configurations.bitcoind.cookie = bitcoind_cookie.clone();
		configurations.lightningd = Some(cln);

		configurations.validate().expect("invalid configuration");

		assert_eq!(configurations.clone().lightningd.unwrap().uri, Uri::from_str(uri.clone().as_str()).unwrap());
		assert_eq!(configurations.clone().lightningd.unwrap().server_cert_path, PathBuf::from(server_cert_path));
		assert_eq!(configurations.clone().lightningd.unwrap().client_cert_path, PathBuf::from(client_cert_path));
		assert_eq!(configurations.clone().lightningd.unwrap().client_key_path, PathBuf::from(client_key_path));
	}

	#[test]
	#[ignore]
	// ignoring this test because concurrency with environment variables is causing problems.
	fn cln_config_from_env_vars() {
		let uri = "http://belson.labs:12345".to_string();
		let server_cert_path = "/hooli/http_public/certs/server.crt".to_string();
		let client_cert_path = "/hooli/http_public/certs/client.crt".to_string();
		let client_key_path = "/hooli/http_public/certs/client.key".to_string();

		env::set_var("ASPD_CLN_URI", uri.clone());
		env::set_var("ASPD_CLN_SERVER_CERT_PATH", server_cert_path.clone());
		env::set_var("ASPD_CLN_CLIENT_CERT_PATH", client_cert_path.clone());
		env::set_var("ASPD_CLN_CLIENT_KEY_PATH", client_key_path.clone());

		let configurations = Config::load(None).unwrap();

		configurations.validate().expect("invalid configuration");

		assert_eq!(configurations.clone().lightningd.unwrap().uri, Uri::from_str(uri.clone().as_str()).unwrap());
		assert_eq!(configurations.clone().lightningd.unwrap().server_cert_path, PathBuf::from(server_cert_path));
		assert_eq!(configurations.clone().lightningd.unwrap().client_cert_path, PathBuf::from(client_cert_path));
		assert_eq!(configurations.clone().lightningd.unwrap().client_key_path, PathBuf::from(client_key_path));

		env::remove_var("ASPD_CLN_URI");
		env::remove_var("ASPD_CLN_SERVER_CERT_PATH");
		env::remove_var("ASPD_CLN_CLIENT_CERT_PATH");
		env::remove_var("ASPD_CLN_CLIENT_KEY_PATH");
	}
}
