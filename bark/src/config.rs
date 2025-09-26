
use std::path::PathBuf;

use bitcoin::{FeeRate, Network};

use bitcoin_ext::BlockHeight;


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
///   ..Config::default()
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
	/// Default value: 288 (48 hrs)
	pub vtxo_refresh_expiry_threshold: BlockHeight,

	/// A fallback fee rate to use in sat/kWu when we fail to retrieve a fee rate from the
	/// configured bitcoind/esplora connection.
	///
	/// Example for 1 sat/vB: --fallback-fee-rate 250
	pub fallback_fee_rate: Option<FeeRate>,
}

impl Config {
	/// A network-dependent default config that sets some useful defaults
	///
	/// The [Default::default] provides a sane default for mainnet
	pub fn network_default(network: Network) -> Self {
		let mut ret = Self::default();
		if network != Network::Bitcoin {
			ret.vtxo_refresh_expiry_threshold = 12;
			ret.fallback_fee_rate = Some(FeeRate::from_sat_per_vb_unchecked(1));
		}
		ret
	}
}

impl Default for Config {
	fn default() -> Config {
		Config {
			server_address: "http://127.0.0.1:3535".to_owned(),
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
			vtxo_refresh_expiry_threshold: 144,
			fallback_fee_rate: None,
		}
	}
}
