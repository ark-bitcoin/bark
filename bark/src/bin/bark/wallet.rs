use std::{path::Path, str::FromStr};

use anyhow::Context;
use bip39::Mnemonic;
use clap::Args;
use tokio::fs;

use bark::{Config, Wallet, db};

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

	#[command(flatten)]
	config: ConfigOpts,
}

pub async fn create_wallet(datadir: &Path, opts: CreateOpts) -> anyhow::Result<()> {
	debug!("Creating wallet in {}", datadir.display());

	if opts.force && datadir.exists() {
		fs::remove_dir_all(datadir).await?;
	}

	// check if dir doesn't exists, then creates it
	if datadir.exists() {
		bail!("Directory {} already exists", datadir.display());
	}
	fs::create_dir_all(&datadir).await.context("can't create dir")?;

	// generate seed
	let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");

	// write it to file
	fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await
		.context("failed to write mnemonic")?;

	info!("Creating new bark Wallet at {}", datadir.display());

	let db = db::Db::open(datadir.join(DB_FILE))?;

	match try_create_wallet(mnemonic, db, opts).await {
		Ok(ok) => Ok(ok),
		Err(err) => {
			// Remove the datadir if it exists
			if datadir.exists() {
				if let Err(e) = fs::remove_dir_all(datadir).await {
					warn!("Failed to remove '{}", datadir.display());
					warn!("{}", e.to_string());
				}
			}
			Err(err)
		}
	}
}

async fn try_create_wallet(mnemonic: Mnemonic, db: db::Db, opts: CreateOpts) -> anyhow::Result<()> {
	let net = if opts.regtest && !opts.signet && !opts.bitcoin{
		bitcoin::Network::Regtest
	} else if opts.signet && !opts.regtest && !opts.bitcoin{
		bitcoin::Network::Signet
	} else if opts.bitcoin && !opts.regtest && !opts.signet {
		warn!("bark is experimental and not yet suited for usage in production");
		bitcoin::Network::Bitcoin
	} else {
		bail!("A network must be specified. Use either --signet, --regtest or --bitcoin");
	};

	let mut config = Config {
		// required args
		asp_address: opts.config.asp.clone().context("ASP address missing, use --asp")?,
		..Default::default()
	};

	opts.config.merge_info(&mut config).context("invalid configuration")?;

	Wallet::create(mnemonic, net, config, db).await.context("error creating wallet")?;

	return Ok(())
}

pub async fn open_wallet(datadir: &Path) -> anyhow::Result<Wallet> {
	debug!("Opening bark wallet in {}", datadir.display());

	// read mnemonic file
	let mnemonic_path = datadir.join(MNEMONIC_FILE);
	let mnemonic_str = fs::read_to_string(&mnemonic_path).await
		.with_context(|| format!("failed to read mnemonic file at {}", mnemonic_path.display()))?;
	let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).context("broken mnemonic")?;

	let db = db::Db::open(datadir.join(DB_FILE))?;

	Wallet::open(&mnemonic, db).await
}
