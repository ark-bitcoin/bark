use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Context;
use bitcoin::Network;
use serde::{Deserialize, Serialize};


/// A Postgres connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Postgres {
	pub host: String,
	#[serde(default = "default_postgres_port")]
	pub port: u16,
	pub name: String,
	pub user: Option<String>,
	#[serde(skip_serializing)]
	pub password: Option<String>,
	#[serde(default = "default_max_connections")]
	pub max_connections: u32,
}

fn default_postgres_port() -> u16 { 5432 }
fn default_max_connections() -> u32 { 10 }

impl Postgres {
	pub fn to_pg_config(&self) -> tokio_postgres::Config {
		let mut cfg = tokio_postgres::Config::new();
		cfg.host(&self.host).port(self.port).dbname(&self.name);
		if let Some(user) = &self.user {
			cfg.user(user);
		}
		if let Some(password) = &self.password {
			cfg.password(password);
		}
		cfg
	}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http {
	/// The address posd listens on.
	pub listen: SocketAddr,
	/// The public base URL, without a trailing slash. Pairing links and the
	/// Lightning address use it.
	pub public_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Barkd {
	/// The base URL of the private barkd that issues forwarding invoices.
	pub url: String,
	/// The barkd bearer token.
	#[serde(skip_serializing)]
	pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Price {
	/// The Bull Bitcoin price API endpoint.
	#[serde(default = "default_price_url")]
	pub url: String,
	/// A fixed price per bitcoin in every currency, in place of the API. For
	/// test networks only.
	pub fixed_btc_price: Option<String>,
	#[serde(default = "default_price_cache_secs")]
	pub cache_secs: u64,
}

fn default_price_url() -> String { "https://api.bullbitcoin.com/public/price".into() }
fn default_price_cache_secs() -> u64 { 60 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sales {
	/// How long an open sale and its invoices stay valid.
	#[serde(default = "default_sale_expiry_secs")]
	pub expiry_secs: u64,
	/// The on-chain minimum for a new store, in sats.
	#[serde(default = "default_onchain_min_sat")]
	pub default_onchain_min_sat: u64,
	/// The largest Lightning address payment, in sats.
	#[serde(default = "default_lnurl_max_sat")]
	pub lnurl_max_sat: u64,
	/// How often the watcher checks open sales.
	#[serde(default = "default_poll_interval_ms")]
	pub poll_interval_ms: u64,
	/// How long the watcher keeps checking an on-chain address after its
	/// sale is final, to record late or extra payments.
	#[serde(default = "default_onchain_watch_secs")]
	pub onchain_watch_secs: u64,
}

fn default_sale_expiry_secs() -> u64 { 600 }
fn default_onchain_min_sat() -> u64 { 50_000 }
fn default_lnurl_max_sat() -> u64 { 10_000_000 }
fn default_poll_interval_ms() -> u64 { 2_000 }
fn default_onchain_watch_secs() -> u64 { 7 * 24 * 3600 }

impl Default for Sales {
	fn default() -> Self {
		Sales {
			expiry_secs: default_sale_expiry_secs(),
			default_onchain_min_sat: default_onchain_min_sat(),
			lnurl_max_sat: default_lnurl_max_sat(),
			poll_interval_ms: default_poll_interval_ms(),
			onchain_watch_secs: default_onchain_watch_secs(),
		}
	}
}

impl Sales {
	pub fn expiry(&self) -> Duration { Duration::from_secs(self.expiry_secs) }
	pub fn poll_interval(&self) -> Duration { Duration::from_millis(self.poll_interval_ms) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	pub network: Network,
	pub http: Http,
	pub postgres: Postgres,
	/// The Ark server's public gRPC address.
	pub ark_server_url: String,
	/// A read-only role on the Ark server's database, with `SELECT` on
	/// `v_arkoor_receive_delivery`.
	pub ark_server_postgres: Postgres,
	pub barkd: Barkd,
	/// The chain source for on-chain payments: a bitcoind, where posd keeps
	/// a watch-only wallet, or an Esplora API. Set exactly one.
	pub bitcoind: Option<crate::rails::onchain::BitcoindConfig>,
	pub esplora_url: Option<String>,
	pub price: Price,
	#[serde(default)]
	pub sales: Sales,
}

impl Config {
	/// Loads a config file, then applies `POSD__` environment variables, for
	/// example `POSD__POSTGRES__HOST`.
	pub fn load(path: Option<&Path>) -> anyhow::Result<Config> {
		let mut builder = config::Config::builder();
		if let Some(path) = path {
			builder = builder.add_source(config::File::from(path));
		}
		builder.add_source(config::Environment::with_prefix("POSD").separator("__"))
			.build().context("failed to read the config")?
			.try_deserialize().context("the config is not valid")
	}
}
