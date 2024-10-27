use std::path::{Path};

use anyhow::Context;
use clap::Args;
use tokio::fs;

use bark::{Config, Wallet};

use crate::ConfigOpts;

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

	if datadir.exists() {
		bail!("Directory {} already exists", datadir.display());
	}

	match try_create_wallet(&datadir, opts).await {
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

async fn try_create_wallet(datadir: &Path, opts: CreateOpts) -> anyhow::Result<()> {
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

	let mut cfg = Config {
		network: net,
		// required args
		asp_address: opts.config.asp.clone().context("ASP address missing, use --asp")?,
		..Default::default()
	};
	opts.config.merge_info(&mut cfg).context("invalid configuration")?;

	Wallet::create(&datadir, cfg).await.context("error creating wallet")?;

	return Ok(())
}
