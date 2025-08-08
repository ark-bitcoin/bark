use std::path::Path;
use std::sync::Arc;
use std::str::FromStr;

use anyhow::Context;
use bark::persist::BarkPersister;
use bitcoin::Network;
use clap::Args;
use log::{debug, info, warn};
use tokio::fs;

use bark::{Config, Wallet as BarkWallet, SqliteClient};
use bark::onchain::OnchainWallet;
use bitcoin_ext::BlockHeight;

use crate::ConfigOpts;

/// File name of the mnemonic file.
const MNEMONIC_FILE: &str = "mnemonic";

/// File name of the database file.
const DB_FILE: &str = "db.sqlite";

#[derive(Args)]
pub struct CreateOpts {
	/// Force re-create the wallet even if it already exists.
	/// Any funds in the old wallet will be lost
	#[arg(long)]
	force: bool,

	/// Use regtest network.
	#[arg(long)]
	regtest: bool,
	/// Use signet network.
	#[arg(long)]
	signet: bool,
	/// Use bitcoin mainnet
	#[arg(long)]
	bitcoin: bool,

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

	let net = match (opts.bitcoin, opts.signet, opts.regtest) {
		(true, false, false) => Network::Bitcoin,
		(false, true, false) => Network::Signet,
		(false, false, true) => Network::Regtest,
		_ => bail!("A network must be specified. Use either --signet, --regtest or --bitcoin"),
	};

	let mut config = Config {
		// required args
		server_address: opts.config.ark.clone().context("Ark server address missing, use --ark")?,
		..Default::default()
	};
	opts.config.merge_into(&mut config).context("invalid configuration")?;

	// check if dir doesn't exists, then create it
	if datadir.exists() {
		if opts.force {
			fs::remove_dir_all(datadir).await?;
		} else {
			bail!("Directory {} already exists", datadir.display());
		}
	}

	if opts.mnemonic.is_some() {
		if opts.birthday_height.is_none() {
			bail!("You need to set the --birthday-height field when recovering from mnemonic.");
		}
		warn!("Recovering from mnemonic currently only supports recovering on-chain funds!");
	} else {
		if opts.birthday_height.is_some() {
			bail!("Can't set --birthday-height if --mnemonic is not set.");
		}
	}

	// Everything that errors after this will wipe the datadir again.
	if let Err(e) = try_create_wallet(&datadir, net, config, opts.mnemonic).await {
		// Remove the datadir if it exists
		if datadir.exists() {
			if let Err(e) = fs::remove_dir_all(datadir).await {
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
) -> anyhow::Result<()> {
	info!("Creating new bark Wallet at {}", datadir.display());

	fs::create_dir_all(datadir).await.context("can't create dir")?;

	// generate seed
	let mnemonic = mnemonic.unwrap_or_else(|| bip39::Mnemonic::generate(12).expect("12 is valid"));
	let seed = mnemonic.to_seed("");
	fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await
		.context("failed to write mnemonic")?;

	// open db
	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE))?);

	let mut onchain = OnchainWallet::load_or_create(net, seed, db.clone())?;
	let wallet = BarkWallet::create_with_onchain(&mnemonic, net, config, db, &onchain).await.context("error creating wallet")?;

	onchain.full_scan(&wallet.chain).await?;
	Ok(())
}

pub async fn open_wallet(datadir: &Path) -> anyhow::Result<(BarkWallet, OnchainWallet)> {
	debug!("Opening bark wallet in {}", datadir.display());

	// read mnemonic file
	let mnemonic_path = datadir.join(MNEMONIC_FILE);
	let mnemonic_str = fs::read_to_string(&mnemonic_path).await
		.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
	let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;
	let seed = mnemonic.to_seed("");

	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE))?);
	let properties = db.read_properties()?.context("failed to read properties")?;

	let bdk_wallet = OnchainWallet::load_or_create(properties.network, seed, db.clone())?;
	let bark_wallet = BarkWallet::open_with_onchain(&mnemonic, db, &bdk_wallet).await?;

	Ok((bark_wallet, bdk_wallet))
}
