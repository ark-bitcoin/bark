
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use bitcoin::{FeeRate, Network};

use bitcoin_ext::{BlockDelta, BlockHeight};


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
}

impl Config {
	/// A network-dependent default config that sets some useful defaults
	///
	/// The [Default::default] provides a sane default for mainnet
	pub fn network_default(network: Network) -> Self {
		let mut ret = Self {
			server_address: "http://127.0.0.1:3535".to_owned(),
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
			vtxo_refresh_expiry_threshold: 144,
			vtxo_exit_margin: 12,
			htlc_recv_claim_delta: 18,
			fallback_fee_rate: None,
			round_tx_required_confirmations: 6,
		};

		if network != Network::Bitcoin {
			ret.vtxo_refresh_expiry_threshold = 12;
			ret.fallback_fee_rate = Some(FeeRate::from_sat_per_vb_unchecked(1));
			ret.round_tx_required_confirmations = 2;
		}

		ret
	}

	/// Load config from the config file path, filling missing fields
	/// from the network default
	pub fn load(network: Network, path: impl AsRef<Path>) -> anyhow::Result<Config> {
		let default = config::Config::try_from(&Self::network_default(network))
			.expect("default config failed to deconstruct");

		Ok(config::Config::builder()
			.add_source(default)
			.add_source(config::File::from(path.as_ref()))
			.build().context("error building config")?
			.try_deserialize::<Config>().context("error parsing config")?)
	}
}

