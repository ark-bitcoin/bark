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
//!     let (bark_wallet, onchain_wallet) = open_wallet(datadir).await?;
//!     // Use the wallets...
//!     Ok(())
//! # }
//! ```

use std::path::Path;
use std::sync::Arc;
use std::str::FromStr;

use anyhow::Context;
use log::{debug, warn};

use bark::{Config, Wallet as BarkWallet, SqliteClient};
use bark::onchain::OnchainWallet;
use bark::persist::BarkPersister;

/// File name of the mnemonic file.
const MNEMONIC_FILE: &str = "mnemonic";

/// File name of the database file.
const DB_FILE: &str = "db.sqlite";

pub async fn open_wallet(datadir: &Path) -> anyhow::Result<(BarkWallet, OnchainWallet)> {
	debug!("Opening bark wallet in {}", datadir.display());

	// read mnemonic file
	let mnemonic_path = datadir.join(MNEMONIC_FILE);
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

	Ok((bark_wallet, bdk_wallet))
}

