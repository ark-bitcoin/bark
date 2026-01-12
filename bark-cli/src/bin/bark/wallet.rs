
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use clap::Args;
use log::{debug, info, warn};

use bark::{BarkNetwork, Config, SqliteClient, Wallet as BarkWallet};
use bark::onchain::OnchainWallet;
use bitcoin_ext::BlockHeight;

use crate::{ConfigOpts, DEBUG_LOG_FILE};

/// File name of the mnemonic file.
const MNEMONIC_FILE: &str = "mnemonic";

/// File name of the database file.
const DB_FILE: &str = "db.sqlite";

const CONFIG_FILE: &str = "config.toml";

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

