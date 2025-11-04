use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use bitcoin::Network;
use clap::Args;
use log::{debug, info, warn};

use bark::{Config, Wallet as BarkWallet, SqliteClient};
use bark::onchain::OnchainWallet;
use bitcoin_ext::BlockHeight;

use crate::ConfigOpts;

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

pub async fn create_wallet(datadir: &Path, opts: CreateOpts) -> anyhow::Result<()> {
	debug!("Creating wallet in {}", datadir.display());

	let net = match (opts.mainnet, opts.signet, opts.regtest, opts.mutinynet) {
		(true,  false, false, false) => Network::Bitcoin,
		(false, true,  false, false) => Network::Signet,
		(false, false, true,  false) => Network::Regtest,
		(false, false, false, true ) => Network::Signet, // mutinynet piggy-backs on Signet params
		_ => bail!("Specify exactly one of --mainnet, --signet, --regtest or --mutinynet"),
	};

	let mut config = Config {
		// required args
		server_address: opts.config.ark.clone().context("Ark server address missing, use --ark")?,
		..Config::network_default(net)
	};

	// Fallback to our default signet backend
	// Only do it when the user did *not* specify either --esplora or --bitcoind.
	if opts.signet && opts.config.esplora.is_none() && opts.config.bitcoind.is_none() {
		config.esplora_address = Some("https://esplora.signet.2nd.dev/".to_owned());
	}

	// Fallback to MutinyNet community Esplora
	// Only do it when the user did *not* specify either --esplora or --bitcoind.
	if opts.mutinynet && opts.config.esplora.is_none() && opts.config.bitcoind.is_none() {
		config.esplora_address = Some("https://mutinynet.com/api".to_owned());
	}

	opts.config.merge_into(&mut config).context("invalid configuration")?;

	// check if dir doesn't exists, then create it
	if datadir.exists() {
		if opts.force {
			tokio::fs::remove_dir_all(datadir).await?;
		} else {
			bail!("Directory {} already exists", datadir.display());
		}
	}

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

	// Everything that errors after this will wipe the datadir again.
	let result = try_create_wallet(
		&datadir, net, config, opts.mnemonic, opts.birthday_height, opts.force,
	).await;
	if let Err(e) = result {
		// Remove the datadir if it exists
		if datadir.exists() {
			if let Err(e) = tokio::fs::remove_dir_all(datadir).await {
				warn!("Failed to remove '{}", datadir.display());
				warn!("{}", e.to_string());
			}
		}
		bail!("Error while creating wallet: {:?}", e);
	}
	Ok(())
}

/// In this method we create the wallet and if it fails, the datadir will be wiped again.
async fn try_create_wallet(
	datadir: &Path,
	net: Network,
	config: Config,
	mnemonic: Option<bip39::Mnemonic>,
	birthday_height: Option<BlockHeight>,
	force: bool,
) -> anyhow::Result<()> {
	info!("Creating new bark Wallet at {}", datadir.display());

	tokio::fs::create_dir_all(datadir).await.context("can't create dir")?;

	// generate seed
	let is_new_wallet = mnemonic.is_none();
	let mnemonic = mnemonic.unwrap_or_else(|| bip39::Mnemonic::generate(12).expect("12 is valid"));
	let seed = mnemonic.to_seed("");
	tokio::fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await
		.context("failed to write mnemonic")?;

	// Write the config to disk
	let toml_string = toml::to_string_pretty(&config).expect("config serialization error");

	let config_path = datadir.join(CONFIG_FILE);
	let mut file = File::create(&config_path)?;
	write!(file, "{}", toml_string)
		.with_context(|| format!("Failed to write config to {}", config_path.display()))?;

	// open db
	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE))?);

	let mut onchain = OnchainWallet::load_or_create(net, seed, db.clone())?;
	let wallet = BarkWallet::create_with_onchain(&mnemonic, net, config, db, &onchain, force).await.context("error creating wallet")?;

	// Skip initial block sync if we generated a new wallet.
	let birthday_height = if is_new_wallet {
		Some(wallet.chain.tip().await?)
	} else {
		birthday_height
	};
	onchain.initial_wallet_scan(&wallet.chain, birthday_height).await?;
	Ok(())
}

