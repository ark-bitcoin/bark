
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::{FeeRate, Network};

use bitcoin_ext::{BlockDelta, BlockHeight};

use crate::chain::ChainSourceSpec;


/// Networks bark can be used on
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BarkNetwork {
	/// Bitcoin's mainnet
	Mainnet,
	/// The official Bitcoin Core signet
	Signet,
	/// Mutinynet
	Mutinynet,
	/// Any regtest network
	Regtest,
}

impl BarkNetwork {
	/// Map to the [Network] types
	pub fn as_bitcoin(&self) -> Network {
		match self {
			Self::Mainnet => Network::Bitcoin,
			Self::Signet => Network::Signet,
			Self::Mutinynet => Network::Signet,
			Self::Regtest => Network::Regtest,
		}
	}
}

impl fmt::Display for BarkNetwork {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    match self {
			Self::Mainnet => f.write_str("mainnet"),
			Self::Signet => f.write_str("signet"),
			Self::Mutinynet => f.write_str("mutinynet"),
			Self::Regtest => f.write_str("regtest"),
		}
	}
}

impl fmt::Debug for BarkNetwork {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

/// Configuration of the Bark wallet.
///
/// - [Config::esplora_address] or [Config::bitcoind_address] must be provided.
/// - If you use [Config::bitcoind_address], you must also provide:
///   - [Config::bitcoind_cookiefile] or
///   - [Config::bitcoind_user] and [Config::bitcoind_pass]
/// - Other optional fields can be omitted.
///
/// # Example
/// Configure the wallet using defaults, then override endpoints for public signet:
///
/// ```rust
/// use bark::Config;
///
/// let cfg = Config {
///   server_address: "https://ark.signet.2nd.dev".into(),
///   esplora_address: Some("https://esplora.signet.2nd.dev".into()),
///   ..Config::network_default(bitcoin::Network::Bitcoin)
/// };
/// // cfg now has all other fields from the default configuration
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// The address of your ark server.
	pub server_address: String,

	/// An access token used to access a private server.
	#[deprecated(
		since = "0.2.4",
		note = "access tokens are not enforced by the server; this field will be removed",
	)]
	pub server_access_token: Option<String>,

	/// Client identifier sent on every RPC to the Ark server (as the
	/// `x-user-agent` header) so server-side telemetry can attribute traffic
	/// per implementation.
	///
	/// Defaults to `bark/<version>` when unset. Integrators embedding bark
	/// (FFI bindings, WASM wallets, custom apps) should set their own value,
	/// e.g. `"aqua/1.4.2"`.
	///
	/// Format: `<name>/<version>`. The name must be 1-32 chars of lowercase
	/// ASCII alphanumeric, `-`, or `_`. Anything else (uppercase, missing
	/// slash, invalid chars, too long) gets the RPC rejected by the server
	/// with `invalid_argument`.
	pub user_agent: Option<String>,

	/// The address of the Esplora HTTP REST server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	pub esplora_address: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
	/// Either `bitcoind_cookiefile` or `bitcoind_user` and `bitcoind_pass` has to be provided.
	pub bitcoind_address: Option<String>,

	/// The path to the bitcoind rpc cookie file.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_cookiefile: Option<PathBuf>,

	/// The bitcoind RPC username.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_user: Option<String>,

	/// The bitcoind RPC password.
	///
	/// Only used with `bitcoind_address`.
	pub bitcoind_pass: Option<String>,

	/// The number of blocks before expiration to refresh vtxos.
	///
	/// Default value: 144 (24h) for mainnet, 12 for testnets
	pub vtxo_refresh_expiry_threshold: BlockHeight,

	/// An upper limit of the number of blocks we expect to need to
	/// safely exit the vtxos.
	///
	/// Default value: 12
	pub vtxo_exit_margin: BlockDelta,

	/// The number of blocks to claim a HTLC-recv VTXO.
	///
	/// Default value: 18
	pub htlc_recv_claim_delta: BlockDelta,

	/// Maximum number of retry attempts when claiming a Lightning receive
	/// against the server fails. After this budget is exhausted, the HTLC-recv
	/// VTXOs will be exited on-chain.
	///
	/// Default value: 5
	pub lightning_receive_claim_retries: u8,

	/// Optional SOCKS5 proxy URL for network traffic.
	///
	/// The proxy is automatically bypassed for localhost addresses
	/// (127.0.0.1, localhost, ::1), so a local bitcoind works without
	/// extra configuration.
	///
	/// Use `socks5h://` to resolve DNS through the proxy which is required for .onion addresses
	/// and to prevent DNS leaks. We don't allow `socks5://` to be used to preserve privacy.
	///
	/// Example: `socks5h://127.0.0.1:9050` for a local Tor daemon.
	#[cfg(feature = "socks5-proxy")]
	pub socks5_proxy: Option<String>,

	/// A fallback fee rate to use in sat/kWu when we fail to retrieve a fee rate from the
	/// configured bitcoind/esplora connection.
	///
	/// Example for 1 sat/vB: --fallback-fee-rate 250
	pub fallback_fee_rate: Option<FeeRate>,

	/// The number of confirmations required before considering a round tx
	/// fully confirmed
	///
	/// Default value: 6 for mainnet, 2 for testnets
	pub round_tx_required_confirmations: BlockHeight,

	/// The number of confirmations required before considering an offboard tx
	/// confirmed. If set to 0, offboard movements are marked as successful
	/// immediately without waiting for confirmation.
	///
	/// Default value: 2 for mainnet
	pub offboard_required_confirmations: BlockHeight,

	/// How long, in seconds, a broadcast offboard tx may be missing from
	/// both chain and mempool before the wallet reports the offboard as
	/// lost. Within the grace period the wallet re-broadcasts the tx
	/// instead: the chain backend might just be slow or out of sync.
	///
	/// Default value: 3600 (one hour)
	pub offboard_lost_tx_grace_period_secs: u64,

	/// Daemon sync interval in seconds for periodic tasks (onchain, exits,
	/// boards, offboards, maintenance, rounds, mailbox).
	///
	/// Default value: 60
	pub daemon_sync_interval_secs: u64,

	/// When set, the daemon skips all automatic wallet syncing — startup
	/// sync, the fast/slow sync intervals, round event subscription, and
	/// the mailbox subscription. Only the server connection heartbeat
	/// keeps running. The operator is responsible for triggering syncs
	/// via the REST API (e.g. `POST /sync`).
	///
	/// Default value: false
	pub daemon_manual_sync: bool,
}

impl Config {
	/// A network-dependent default config that sets some useful defaults
	///
	/// The [Default::default] provides a sane default for mainnet
	pub fn network_default(network: Network) -> Self {
		#[allow(deprecated)]
		let mut ret = Self {
			server_address: "http://127.0.0.1:3535".to_owned(),
			server_access_token: None,
			user_agent: None,
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
			#[cfg(feature = "socks5-proxy")]
			socks5_proxy: None,
			vtxo_refresh_expiry_threshold: 144,
			vtxo_exit_margin: 12,
			htlc_recv_claim_delta: 18,
			lightning_receive_claim_retries: 5,
			fallback_fee_rate: Some(FeeRate::from_sat_per_vb_u32(2)),
			round_tx_required_confirmations: 1,
			offboard_required_confirmations: 2,
			offboard_lost_tx_grace_period_secs: 3600,
			daemon_sync_interval_secs: 60,
			daemon_manual_sync: false,
		};

		if network != Network::Bitcoin {
			ret.vtxo_refresh_expiry_threshold = 12;
			ret.fallback_fee_rate = Some(FeeRate::from_sat_per_vb_u32(1));
			ret.round_tx_required_confirmations = 1;
			ret.offboard_required_confirmations = 0;
		}

		ret
	}

	/// Load config from the config file path, filling missing fields
	/// from the network default.
	///
	/// Config values are loaded in the following priority order (highest to lowest):
	/// 1. Environment variables with `BARK_` prefix (e.g., `BARK_ESPLORA_ADDRESS`)
	/// 2. Config file values
	/// 3. Network defaults
	pub fn load(network: Network, path: impl AsRef<Path>) -> anyhow::Result<Config> {
		let default = config::Config::try_from(&Self::network_default(network))
			.expect("default config failed to deconstruct");

		Ok(config::Config::builder()
			.add_source(default)
			.add_source(config::File::from(path.as_ref()).required(false))
			.add_source(config::Environment::with_prefix("BARK"))
			.build().context("error building config")?
			.try_deserialize::<Config>().context("error parsing config")?)
	}

	/// Creates a [crate::chain::ChainSource] instance to communicate with a chain
	/// backend from this [Config].
	pub fn chain_source(&self) -> anyhow::Result<ChainSourceSpec> {
		if let Some(ref url) = self.esplora_address {
			Ok(ChainSourceSpec::Esplora {
				url: url.clone(),
			})
		} else if let Some(ref url) = self.bitcoind_address {
			let auth = if let Some(ref c) = self.bitcoind_cookiefile {
				bitcoin_ext::rpc::Auth::CookieFile(c.clone())
			} else {
				bitcoin_ext::rpc::Auth::UserPass(
					self.bitcoind_user.clone().context("need bitcoind auth config")?,
					self.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			Ok(ChainSourceSpec::Bitcoind {
				url: url.clone(),
				auth,
			})
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		}
	}
}

