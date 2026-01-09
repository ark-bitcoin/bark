//! Wallet utilities
//!
//! Opens a Bark wallet and its on-chain companion from a data directory.
//!
//! ## Behavior
//! - Reads a BIP-39 `mnemonic` file from the provided directory
//! - Parses `config.toml` into a [`bark::Config`]
//! - Opens `db.sqlite` as a [`bark::SqliteClient`] and loads persisted properties
//! - Loads or creates the [`bark::onchain::OnchainWallet`]
//! - Opens the [`bark::Wallet`] bound to the on-chain wallet
//! - Returns `(bark::Wallet, bark::onchain::OnchainWallet)`
//!
//! ## Errors
//! Returns an [`anyhow::Error`] with context describing the failing step (I/O, parsing,
//! database access, or wallet initialization).
//!
//! ## Example
//! Open a wallet from a data directory:
//!
//! ```rust,no_run
//! # use std::path::Path;
//! # use bark_cli::wallet::open_wallet;
//! # async fn example() -> anyhow::Result<()> {
//!     let datadir = Path::new("./bark_data");
//!     let (bark_wallet, onchain_wallet) = open_wallet(datadir).await?.unwrap();
//!     // Use the wallets...
//!     Ok(())
//! # }
//! ```

use std::path::Path;
use std::sync::Arc;
use std::str::FromStr;

use anyhow::{Context, bail};
use bitcoin::Network;
use clap::Args;
use log::{debug, info, warn};

use bark::{BarkNetwork, Config, Wallet as BarkWallet, SqliteClient};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;

use bitcoin_ext::BlockHeight;

use crate::util;

/// File name of the mnemonic file.
const MNEMONIC_FILE: &str = "mnemonic";

/// File name of the database file.
const DB_FILE: &str = "db.sqlite";

/// File name of the config file.
const CONFIG_FILE: &str = "config.toml";

/// File name of the debug log file.
const DEBUG_LOG_FILE: &str = "debug.log";

/// Options to define the initial bark config
#[derive(Clone, PartialEq, Eq, Default, clap::Args)]
struct ConfigOpts {
	/// The address of your Ark server.
	#[arg(long)]
	ark: Option<String>,

	/// The address of the Esplora HTTP server to use.
	///
	/// Either this or the `bitcoind_address` field has to be provided.
	#[arg(long)]
	esplora: Option<String>,

	/// The address of the bitcoind RPC server to use.
	///
	/// Either this or the `esplora_address` field has to be provided.
	#[arg(long)]
	bitcoind: Option<String>,

	/// The path to the bitcoind rpc cookie file.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_cookie: Option<String>,

	/// The bitcoind RPC username.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_user: Option<String>,

	/// The bitcoind RPC password.
	///
	/// Only used with `bitcoind_address`.
	#[arg(long)]
	bitcoind_pass: Option<String>,
}

impl ConfigOpts {
	/// Fill the default required config fields based on network
	fn fill_network_defaults(&mut self, net: BarkNetwork) {
		// Fallback to our default signet backend
		// Only do it when the user did *not* specify either --esplora or --bitcoind.
		if net == BarkNetwork::Signet && self.esplora.is_none() && self.bitcoind.is_none() {
			self.esplora = Some("https://esplora.signet.2nd.dev/".to_owned());
		}

		// Fallback to Mutinynet community Esplora
		// Only do it when the user did *not* specify either --esplora or --bitcoind.
		if net == BarkNetwork::Mutinynet && self.esplora.is_none() && self.bitcoind.is_none() {
			self.esplora = Some("https://mutinynet.com/api".to_owned());
		}
	}

	/// Validate the config options are sane
	fn validate(&self) -> anyhow::Result<()> {
		if self.esplora.is_none() && self.bitcoind.is_none() {
			bail!("You need to provide a chain source using either --esplora or --bitcoind");
		}

		match (
			self.bitcoind.is_some(),
			self.bitcoind_cookie.is_some(),
			self.bitcoind_user.is_some(),
			self.bitcoind_pass.is_some(),
		) {
			(false, false, false, false) => {},
			(false, _, _, _) => bail!("Provided bitcoind auth args without bitcoind address"),
			(_, true, false, false) => {},
			(_, true, _, _) => bail!("Bitcoind user/pass shouldn't be provided together with cookie file"),
			(_, _, true, true) => {},
			_ => bail!("When providing --bitcoind, you need to provide auth args as well."),
		}

		Ok(())
	}

	/// Will write the provided config options to the config
	///
	/// Will also load and return the config when loaded from the written file.
	fn write_to_file(&self, network: Network, path: impl AsRef<Path>) -> anyhow::Result<Config> {
		use std::fmt::Write;

		let mut conf = String::new();
		let ark = util::default_scheme("https", self.ark.as_ref().context("missing --ark arg")?)
			.context("invalid ark server URL")?;
		writeln!(conf, "server_address = \"{}\"", ark).unwrap();

		if let Some(ref v) = self.esplora {
			let url = util::default_scheme("https", v).context("invalid esplora URL")?;
			writeln!(conf, "esplora_address = \"{}\"", url).unwrap();
		}
		if let Some(ref v) = self.bitcoind {
			let url = util::default_scheme("http", v).context("invalid bitcoind URL")?;
			writeln!(conf, "bitcoind_address = \"{}\"", url).unwrap();
		}
		if let Some(ref v) = self.bitcoind_cookie {
			writeln!(conf, "bitcoind_cookiefile = \"{}\"", v).unwrap();
		}
		if let Some(ref v) = self.bitcoind_user {
			writeln!(conf, "bitcoind_user = \"{}\"", v).unwrap();
		}
		if let Some(ref v) = self.bitcoind_pass {
			writeln!(conf, "bitcoind_pass = \"{}\"", v).unwrap();
		}

		let path = path.as_ref();
		std::fs::write(path, conf).with_context(|| format!(
			"error writing new config file to {}", path.display(),
		))?;

		// new let's try load it to make sure it's sane
		Ok(Config::load(network, path).context("problematic config flags provided")?)
	}
}

#[derive(Args)]
pub struct CreateOpts {
	/// Force re-create the wallet even if it already exists.
	/// Any funds in the old wallet will be lost
	#[arg(long)]
	force: bool,

	/// Use bitcoin mainnet
	#[arg(long)]
	mainnet: bool,
	/// Use regtest network
	#[arg(long)]
	regtest: bool,
	/// Use the official signet network
	#[arg(long)]
	signet: bool,
	/// Use mutinynet
	#[arg(long)]
	mutinynet: bool,

	/// Recover a wallet with an existing mnemonic.
	/// This currently only works for on-chain funds.
	#[arg(long)]
	mnemonic: Option<bip39::Mnemonic>,

	/// The wallet/mnemonic's birthday blockheight to start syncing when recovering.
	#[arg(long)]
	birthday_height: Option<BlockHeight>,

	#[command(flatten)]
	config: ConfigOpts,
}

/// Checks the config file and maybe cleans it
/// - returns whether a config file was present
/// - if clean is false, errors if any file not config or logs is present
/// - if clean is true, removes all files not config or logs
async fn check_clean_datadir(datadir: &Path, clean: bool) -> anyhow::Result<bool> {
	let mut has_config = false;
	if datadir.exists() {
		for item in datadir.read_dir().context("error accessing datadir")? {
			let item = item.context("error reading existing content of datadir")?;

			if item.file_name() == CONFIG_FILE {
				has_config = true;
				continue;
			}
			if item.file_name() == DEBUG_LOG_FILE {
				continue;
			}

			if !clean {
				bail!("Datadir has unexpected contents: {}", item.path().display());
			}

			// otherwise try wipe
			let file_type = item.file_type().context("error accessing datadir content")?;
			if file_type.is_dir() {
				tokio::fs::remove_dir_all(item.path()).await.context("error deleting datadir content")?;
			} else if file_type.is_file() || file_type.is_symlink() {
				tokio::fs::remove_file(item.path()).await.context("error deleting datadir content")?;
			} else {
				// can't happen
				bail!("non-existent file type in ");
			}
		}
	}
	Ok(has_config)
}

pub async fn create_wallet(datadir: &Path, opts: CreateOpts) -> anyhow::Result<()> {
	debug!("Creating wallet in {}", datadir.display());

	let net = match (opts.mainnet, opts.signet, opts.regtest, opts.mutinynet) {
		(true,  false, false, false) => BarkNetwork::Mainnet,
		(false, true,  false, false) => BarkNetwork::Signet,
		(false, false, true,  false) => BarkNetwork::Regtest,
		(false, false, false, true ) => BarkNetwork::Mutinynet,
		_ => bail!("Specify exactly one of --mainnet, --signet, --regtest or --mutinynet"),
	};

	// check for non-config file contents in the datadir and wipe if force
	let config_existed = check_clean_datadir(datadir, opts.force).await?;

	// Everything that errors after this will wipe the datadir again.
	let result = try_create_wallet(datadir, net, opts).await;
	if let Err(e) = result {
		if config_existed {
			if let Err(e) = check_clean_datadir(datadir, true).await {
				warn!("Error cleaning datadir after failure: {:#}", e);
			}
		} else {
			if let Err(e) = tokio::fs::remove_dir_all(datadir).await {
				warn!("Error removing datadir after failure: {:#}", e);
			}
		}

		bail!("Error while creating wallet: {:#}", e);
	}
	Ok(())
}

/// In this method we create the wallet and if it fails, the datadir will be wiped again.
async fn try_create_wallet(
	datadir: &Path,
	net: BarkNetwork,
	mut opts: CreateOpts,
) -> anyhow::Result<()> {
	info!("Creating new bark Wallet at {}", datadir.display());

	tokio::fs::create_dir_all(datadir).await.context("can't create dir")?;

	let config_path = datadir.join(CONFIG_FILE);
	let has_config_args = opts.config != ConfigOpts::default();
	let config = match (config_path.exists(), has_config_args) {
		(true, false) => {
			Config::load(net.as_bitcoin(), &config_path).with_context(|| format!(
				"error loading existing config file at {}", config_path.display(),
			))?
		},
		(false, true) => {
			opts.config.fill_network_defaults(net);
			opts.config.validate().context("invalid config options")?;
			opts.config.write_to_file(net.as_bitcoin(), config_path)?
		},
		(false, false) => bail!("You need to provide config flags or a config file"),
		(true, true) => bail!("Cannot provide an existing config file and config flags"),
	};

	// A mnemonic implies that the user wishes to recover an existing wallet.
	if opts.mnemonic.is_some() {
		if opts.birthday_height.is_none() {
			// Only Bitcoin Core requires a birthday height to avoid syncing the entire chain.
			if config.bitcoind_address.is_some() {
				bail!("You need to set the --birthday-height field when recovering from mnemonic.");
			}
		} else if config.esplora_address.is_some() {
			warn!("The given --birthday-height will be ignored because you're using Esplora.");
		}
		warn!("Recovering from mnemonic currently only supports recovering on-chain funds!");
	} else {
		if opts.birthday_height.is_some() {
			bail!("Can't set --birthday-height if --mnemonic is not set.");
		}
	}

	// generate seed
	let is_new_wallet = opts.mnemonic.is_none();
	let mnemonic = opts.mnemonic.unwrap_or_else(|| bip39::Mnemonic::generate(12).expect("12 is valid"));
	let seed = mnemonic.to_seed("");
	tokio::fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await
		.context("failed to write mnemonic")?;

	// open db
	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE))?);

	let mut onchain = OnchainWallet::load_or_create(net.as_bitcoin(), seed, db.clone()).await?;
	let wallet = BarkWallet::create_with_onchain(
		&mnemonic, net.as_bitcoin(), config, db, &onchain, opts.force,
	).await.context("error creating wallet")?;

	// Skip initial block sync if we generated a new wallet.
	let birthday_height = if is_new_wallet {
		Some(wallet.chain.tip().await?)
	} else {
		opts.birthday_height
	};
	onchain.initial_wallet_scan(&wallet.chain, birthday_height).await?;
	Ok(())
}

pub async fn open_wallet(datadir: &Path) -> anyhow::Result<Option<(BarkWallet, OnchainWallet)>> {
	debug!("Opening bark wallet in {}", datadir.display());


	// read mnemonic file
	let mnemonic_path = datadir.join(MNEMONIC_FILE);

	if !tokio::fs::try_exists(datadir).await? {
		return Ok(None);
	}

	let mnemonic_str = tokio::fs::read_to_string(&mnemonic_path).await
		.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
	let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;
	let seed = mnemonic.to_seed("");

	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE))?);
	let properties = db.read_properties().await?.context("failed to read properties")?;

	// Read the config
	let config_path = datadir.join("config.toml");
	let config = Config::load(properties.network, config_path)
		.context("error loading bark config file")?;

	let bdk_wallet = OnchainWallet::load_or_create(properties.network, seed, db.clone()).await?;
	let bark_wallet = BarkWallet::open_with_onchain(&mnemonic, db, &bdk_wallet, config).await?;

	if let Err(e) = bark_wallet.require_chainsource_version() {
		warn!("{}", e);
	}

	Ok(Some((bark_wallet, bdk_wallet)))
}

