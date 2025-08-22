
use std::path::PathBuf;

use bitcoin::FeeRate;

use bitcoin_ext::BlockHeight;


/// Configuration of the Bark wallet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
	/// The address of your server.
	pub server_address: String,

	/// The address of the Esplora HTTP server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	pub esplora_address: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
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

impl Default for Config {
	fn default() -> Config {
		Config {
			server_address: "http://127.0.0.1:3535".to_owned(),
			esplora_address: None,
			bitcoind_address: None,
			bitcoind_cookiefile: None,
			bitcoind_user: None,
			bitcoind_pass: None,
			vtxo_refresh_expiry_threshold: 288,
			fallback_fee_rate: None,
		}
	}
}
