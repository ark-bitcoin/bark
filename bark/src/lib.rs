//! ![bark: Ark on bitcoin](https://gitlab.com/ark-bitcoin/bark/-/raw/master/assets/bark-header-white.jpg)
//!
//! <div align="center">
//! <h1>Bark: Ark on bitcoin</h1>
//! <p>Fast, low-cost, self-custodial payments on bitcoin.</p>
//! </div>
//!
//! <p align="center">
//! <br />
//! <a href="https://docs.second.tech">Docs</a> ·
//! <a href="https://gitlab.com/ark-bitcoin/bark/-/issues">Issues</a> ·
//! <a href="https://second.tech">Website</a> ·
//! <a href="https://blog.second.tech">Blog</a> ·
//! <a href="https://www.youtube.com/@2ndbtc">YouTube</a>
//! </p>
//!
//! <div align="center">
//!
//! [![Release](https://img.shields.io/gitlab/v/release/ark-bitcoin/bark?gitlab_url=https://gitlab.com&sort=semver&label=release)
//! [![Project Status](https://img.shields.io/badge/status-experimental-red.svg)](https://gitlab.com/ark-bitcoin/bark)
//! [![License](https://img.shields.io/badge/license-CC0--1.0-blue.svg)](https://gitlab.com/ark-bitcoin/bark/-/blob/master/LICENSE)
//! [![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=git)](https://gitlab.com/ark-bitcoin/bark/-/blob/master/CONTRIBUTING.md)
//! [![Community](https://img.shields.io/badge/community-forum-blue?logo=discourse)](https://community.second.tech)
//!
//! </div>
//! <br />
//!
//! Bark is an implementation of the Ark protocol on bitcoin, led by [Second](https://second.tech).
//!
//! # A tour of Bark
//!
//! Integrating the Ark-protocol offers
//!
//! - 🏃‍♂️ **Smooth boarding**: No channels to open, no on-chain setup required—create a wallet and start transacting
//! - 🤌 **Simplified UX**: Send and receive without managing channels, liquidity, or routing
//! - 🌐 **Universal payments**: Send Ark, Lightning, and on-chain payments from a single off-chain balance
//! - 🔌 **Easier integration**: Client-server architecture reduces complexity compared to P2P protocols
//! - 💸 **Lower costs**: Instant payments at a fraction of on-chain fees
//! - 🔒 **Self-custodial**: Users maintain full control of their funds at all times
//!
//! This guide puts focus on how to use the Rust-API and assumes
//! some basic familiarity with the Ark protocol. We refer to the
//! [protocol docs](http://docs.second.tech/ark-protocol) for an introduction.
//!
//! ## Creating an Ark wallet
//!
//! The user experience of setting up an Ark wallet is pretty similar
//! to setting up an onchain wallet. You need to provide a [bip39::Mnemonic] which
//! can be used to recover funds. Typically, most apps request the user
//! to write down the mnemonic or ensure they use another method for a secure back-up.
//!
//! The user can select an Ark server and a [chain::ChainSource] as part of
//! the configuration. The example below configures
//!
//! You will also need a place to store all [ark::Vtxo]s on the users device.
//! We have implemented [SqliteClient] which is a sane default on most devices.
//! However, it is possible to implement a [BarkPersister] if you have other
//! requirements.
//!
//! The code-snippet below shows how you can create a [Wallet].
//!
//! ```no_run
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use tokio::fs;
//! use bark::{Config, onchain, SqliteClient, Wallet};
//!
//! const MNEMONIC_FILE : &str = "mnemonic";
//! const DB_FILE: &str = "db.sqlite";
//!
//! #[tokio::main]
//! async fn main() {
//! 	// Pick the bitcoin network that will be used
//! 	let network = bitcoin::Network::Signet;
//!
//! 	// Configure the wallet
//! 	let config = Config {
//! 		server_address: String::from("https://ark.signet.2nd.dev"),
//! 		esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
//! 		..Config::network_default(network)
//! 	};
//!
//!
//! 	// Create a sqlite database
//! 	let datadir = PathBuf::from("./bark");
//! 	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
//!
//! 	// Generate and seed and store it somewhere
//! 	let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
//! 	fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await.unwrap();
//!
//! 	let wallet = Wallet::create(
//! 		&mnemonic,
//! 		network,
//! 		config,
//! 		db,
//! 		false
//! 	).await.unwrap();
//! }
//! ```
//!
//! ## Opening an existing Ark wallet
//!
//! The [Wallet] can be opened again by providing the [bip39::Mnemonic] and
//! the [BarkPersister] again. Note, that [SqliteClient] implements the [BarkPersister]-trait.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::path::PathBuf;
//! # use std::str::FromStr;
//! #
//! # use bip39;
//! # use tokio::fs;
//! #
//! # use bark::{Config, SqliteClient, Wallet};
//! #
//! const MNEMONIC_FILE : &str = "mnemonic";
//! const DB_FILE: &str = "db.sqlite";
//!
//! #[tokio::main]
//! async fn main() {
//! 	let datadir = PathBuf::from("./bark");
//! 	let config = Config {
//! 		server_address: String::from("https://ark.signet.2nd.dev"),
//! 		esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
//! 		..Config::network_default(bitcoin::Network::Signet)
//! 	};
//!
//! 	let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
//! 	let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
//! 	let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! 	let wallet = Wallet::open(&mnemonic, db, config).await.unwrap();
//! }
//! ```
//!
//! ## Receiving coins
//!
//! For the time being we haven't implemented an Ark address type (yet). You
//! can send funds directly to a public key.
//!
//! If you are on signet and your Ark server is [https://ark.signet.2nd.dev](https://ark.signet.2nd.dev),
//! you can request some sats from our [faucet](https://signet.2nd.dev).
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::str::FromStr;
//! # use std::path::PathBuf;
//! #
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, SqliteClient};
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! # const DB_FILE: &str = "db.sqlite";
//! #
//! # async fn get_wallet() -> Wallet {
//! 	#   let datadir = PathBuf::from("./bark");
//! 	#   let config = Config::network_default(bitcoin::Network::Signet);
//! 	#
//! 	#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
//! 	#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
//! 	#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! 	#   Wallet::open(&mnemonic, db, config).await.unwrap()
//! 	# }
//! #
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//! 	let wallet = get_wallet().await;
//! 	let address: ark::Address = wallet.new_address().await?;
//! 	Ok(())
//! }
//! ```
//!
//! ## Inspecting the wallet
//!
//! An Ark wallet contains [ark::Vtxo]s. These are just like normal utxos
//! in a bitcoin wallet. They just haven't been confirmed on chain (yet).
//! However, the user remains in full control of the funds and can perform
//! a unilateral exit at any time.
//!
//! The snippet below shows how you can inspect your [WalletVtxo]s.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::str::FromStr;
//! # use std::path::PathBuf;
//! #
//! # use tokio::fs;
//! #
//! # use bark::{Config, SqliteClient, Wallet};
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! # const DB_FILE: &str = "db.sqlite";
//! #
//! # async fn get_wallet() -> Wallet {
//! 	#   let datadir = PathBuf::from("./bark");
//! 	#
//! 	#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
//! 	#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
//! 	#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! 	#
//! 	#   let config = Config::network_default(bitcoin::Network::Signet);
//! 	#
//! 	#   Wallet::open(&mnemonic, db, config).await.unwrap()
//! 	# }
//! #
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//! 	let mut wallet = get_wallet().await;
//!
//! 	// The vtxo's command doesn't sync your wallet
//! 	// Make sure your app is synced before inspecting the wallet
//! 	wallet.sync().await;
//!
//! 	let vtxos: Vec<bark::WalletVtxo> = wallet.vtxos().await.unwrap();
//! 	Ok(())
//! }
//! ```
//!
//! Use [Wallet::balance] if you are only interested in the balance.
//!
//! ## Participating in a round
//!
//! You can participate in a round to refresh your coins. Typically,
//! you want to refresh coins which are soon to expire or you might
//! want to aggregate multiple small vtxos to keep the cost of exit
//! under control.
//!
//! As a wallet developer you can implement your own refresh strategy.
//! This gives you full control over which [ark::Vtxo]s are refreshed and
//! which aren't.
//!
//! This example uses [RefreshStrategy::must_refresh] which is a sane
//! default that selects all [ark::Vtxo]s that must be refreshed.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::str::FromStr;
//! # use std::path::PathBuf;
//! #
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, SqliteClient};
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! # const DB_FILE: &str = "db.sqlite";
//! #
//! # async fn get_wallet() -> Wallet {
//! 	#   let datadir = PathBuf::from("./bark");
//! 	#
//! 	#   let db = Arc::new(SqliteClient::open(datadir.join(DB_FILE)).unwrap());
//! 	#   let mnemonic_str = fs::read_to_string(datadir.join(DB_FILE)).await.unwrap();
//! 	#   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! 	#
//! 	#   let config = Config::network_default(bitcoin::Network::Signet);
//! 	#
//! 	#   Wallet::open(&mnemonic, db, config).await.unwrap()
//! 	# }
//! #
//! use bark::vtxo::RefreshStrategy;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//! 	let wallet = get_wallet().await;
//!
//! 	// Select all vtxos that refresh soon
//! 	let tip = wallet.chain.tip().await?;
//! 	let fee_rate = wallet.chain.fee_rates().await.fast;
//! 	let strategy = RefreshStrategy::must_refresh(&wallet, tip, fee_rate);
//!
//! 	let vtxos = wallet.spendable_vtxos_with(&strategy).await?;
//!		wallet.refresh_vtxos(vtxos).await?;
//! 	Ok(())
//! }
//! ```



pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;

pub mod chain;
pub mod exit;
pub mod movement;
pub mod onchain;
pub mod persist;
pub mod round;
pub mod subsystem;
pub mod vtxo;

mod arkoor;
mod board;
mod config;
mod daemon;
mod lightning;
mod offboard;
mod psbtext;
mod mailbox;

pub use self::arkoor::ArkoorCreateResult;
pub use self::config::{BarkNetwork, Config};
pub use self::daemon::DaemonHandle;
pub use self::persist::sqlite::SqliteClient;
pub use self::vtxo::WalletVtxo;

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Amount, Network, OutPoint};
use bitcoin::bip32::{self, ChildNumber, Fingerprint};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use log::{trace, info, warn, error};
use tokio::sync::{Mutex, RwLock};

use ark::lightning::PaymentHash;

use ark::{ArkInfo, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::address::VtxoDelivery;
use ark::fees::{validate_and_subtract_fee_min_dust, VtxoFeeInfo};
use ark::mailbox::MailboxIdentifier;
use ark::vtxo::{PubkeyVtxoPolicy, VtxoRef};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, P2TR_DUST};
use server_rpc::{protos, ServerConnection};

use crate::chain::{ChainSource, ChainSourceSpec};
use crate::exit::Exit;
use crate::movement::Movement;
use crate::movement::manager::MovementManager;
use crate::movement::update::MovementUpdate;
use crate::onchain::{DaemonizableOnchainWallet, ExitUnilaterally, PreparePsbt, SignPsbt, Utxo};
use crate::persist::{BarkPersister, RoundStateId, StoredRoundState};
use crate::round::{RoundParticipation, RoundStatus};
use crate::subsystem::{ArkoorMovement, RoundMovement};
use crate::vtxo::{FilterVtxos, RefreshStrategy, VtxoFilter, VtxoStateKind};

/// Derivation index for Bark usage
const BARK_PURPOSE_INDEX: u32 = 350;
/// Derivation index used to generate keypairs to sign VTXOs
const VTXO_KEYS_INDEX: u32 = 0;
/// Derivation index used to generate keypair for the mailbox
const MAILBOX_KEY_INDEX: u32 = 1;

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Logs an error message for when the server public key has changed.
///
/// This warns the user that the server pubkey has changed and recommends
/// performing an emergency exit to recover their funds on-chain.
fn log_server_pubkey_changed_error(expected: PublicKey, got: PublicKey) {
	error!(
	    "
Server public key has changed!

The Ark server's public key is different from the one stored when this
wallet was created. This typically happens when:

	- The server operator has rotated their keys
	- You are connecting to a different server
	- The server has been replaced

For safety, this wallet will not connect to the server until you
resolve this. You can recover your funds on-chain by doing an emergency exit.

This will exit your VTXOs to on-chain Bitcoin without needing the server's cooperation.

Expected: {expected}
Got:      {got}")
}

/// The detailled balance of a Lightning receive.
#[derive(Debug, Clone)]
pub struct LightningReceiveBalance {
	/// Sum of all pending lightning invoices
	pub total: Amount,
	/// Sum of all invoices for which we received the HTLC VTXOs
	pub claimable: Amount,
}

/// The different balances of a Bark wallet.
#[derive(Debug, Clone)]
pub struct Balance {
	/// Coins that are spendable in the Ark, either in-round or out-of-round.
	pub spendable: Amount,
	/// Coins that are in the process of being sent over Lightning.
	pub pending_lightning_send: Amount,
	/// Coins that are in the process of being received over Lightning.
	pub claimable_lightning_receive: Amount,
	/// Coins locked in a round.
	pub pending_in_round: Amount,
	/// Coins that are in the process of unilaterally exiting the Ark.
	/// None if exit subsystem was unavailable
	pub pending_exit: Option<Amount>,
	/// Coins that are pending sufficient confirmations from board transactions.
	pub pending_board: Amount,
}

pub struct UtxoInfo {
	pub outpoint: OutPoint,
	pub amount: Amount,
	pub confirmation_height: Option<u32>,
}

impl From<Utxo> for UtxoInfo {
	fn from(value: Utxo) -> Self {
		match value {
			Utxo::Local(o) => UtxoInfo {
				outpoint: o.outpoint,
				amount: o.amount,
				confirmation_height: o.confirmation_height,
			},
			Utxo::Exit(e) => UtxoInfo {
				outpoint: e.vtxo.point(),
				amount: e.vtxo.amount(),
				confirmation_height: Some(e.height),
			},
		}
	}
}

/// Represents an offchain balance structure consisting of available funds, pending amounts in
/// unconfirmed rounds, and pending exits.
pub struct OffchainBalance {
	/// Funds currently available for use. This reflects the spendable balance.
	pub available: Amount,
	/// Funds that are pending in unconfirmed operational rounds.
	pub pending_in_round: Amount,
	/// Funds being unilaterally exited. These may require more onchain confirmations to become
	/// available onchain.
	pub pending_exit: Amount,
}

/// Read-only properties of the Bark wallet.
#[derive(Debug, Clone)]
pub struct WalletProperties {
	/// The Bitcoin network to run Bark on.
	///
	/// Default value: signet.
	pub network: Network,

	/// The wallet fingerpint
	///
	/// Used on wallet loading to check mnemonic correctness
	pub fingerprint: Fingerprint,

	/// The server public key from the initial connection.
	///
	/// This is used to detect if the Ark server has been replaced,
	/// which could indicate a malicious server. If the server pubkey
	/// changes, the wallet will refuse to connect and warn the user
	/// to perform an emergency exit.
	pub server_pubkey: Option<PublicKey>,
}

/// Struct representing an extended private key derived from a
/// wallet's seed, used to derive child VTXO keypairs
///
/// The VTXO seed is derived by applying a hardened derivation
/// step at index 350 from the wallet's seed.
pub struct WalletSeed {
	master: bip32::Xpriv,
	vtxo: bip32::Xpriv,
}

impl WalletSeed {
	fn new(network: Network, seed: &[u8; 64]) -> Self {
		let bark_path = [ChildNumber::from_hardened_idx(BARK_PURPOSE_INDEX).unwrap()];
		let master = bip32::Xpriv::new_master(network, seed)
			.expect("invalid seed")
			.derive_priv(&SECP, &bark_path)
			.expect("purpose is valid");

		let vtxo_path = [ChildNumber::from_hardened_idx(VTXO_KEYS_INDEX).unwrap()];
		let vtxo = master.derive_priv(&SECP, &vtxo_path)
			.expect("vtxo path is valid");

		Self { master, vtxo }
	}

	fn fingerprint(&self) -> Fingerprint {
		self.master.fingerprint(&SECP)
	}

	fn derive_vtxo_keypair(&self, idx: u32) -> Keypair {
		self.vtxo.derive_priv(&SECP, &[idx.into()]).unwrap().to_keypair(&SECP)
	}

	fn to_mailbox_keypair(&self) -> Keypair {
		let mailbox_path = [ChildNumber::from_hardened_idx(MAILBOX_KEY_INDEX).unwrap()];
		self.master.derive_priv(&SECP, &mailbox_path).unwrap().to_keypair(&SECP)
	}
}

/// The central entry point for using this library as an Ark wallet.
///
/// Overview
/// - Wallet encapsulates the complete Ark client implementation:
///   - address generation (Ark addresses/keys)
///     - [Wallet::new_address],
///     - [Wallet::new_address_with_index],
///     - [Wallet::peak_address],
///     - [Wallet::validate_arkoor_address]
///   - boarding onchain funds into Ark from an onchain wallet (see [onchain::OnchainWallet])
///     - [Wallet::board_amount],
///     - [Wallet::board_all]
///   - offboarding Ark funds to move them back onchain
///     - [Wallet::offboard_vtxos],
///     - [Wallet::offboard_all]
///   - sending and receiving Ark payments (including to BOLT11/BOLT12 invoices)
///     - [Wallet::send_arkoor_payment],
///     - [Wallet::pay_lightning_invoice],
///     - [Wallet::pay_lightning_address],
///     - [Wallet::pay_lightning_offer]
///   - tracking, selecting, and refreshing VTXOs
///     - [Wallet::vtxos],
///     - [Wallet::vtxos_with],
///     - [Wallet::refresh_vtxos]
///   - syncing with the Ark server, unilateral exits and performing general maintenance
///     - [Wallet::maintenance]: Syncs everything offchain-related and refreshes VTXOs where
///       necessary,
///     - [Wallet::maintenance_with_onchain]: The same as [Wallet::maintenance] but also syncs the
///       onchain wallet and unilateral exits,
///     - [Wallet::maintenance_refresh]: Refreshes VTXOs where necessary without syncing anything,
///     - [Wallet::sync]: Syncs network fee-rates, ark rounds and arkoor payments,
///     - [Wallet::sync_exits]: Updates the status of unilateral exits,
///     - [Wallet::sync_pending_lightning_send_vtxos]: Updates the status of pending lightning payments,
///     - [Wallet::try_claim_all_lightning_receives]: Wait for payment receipt of all open invoices, then claim them,
///     - [Wallet::sync_pending_boards]: Registers boards which are available for use
///       in offchain payments
///
/// Key capabilities
/// - Address management:
///   - derive and peek deterministic Ark addresses and their indices
/// - Funds lifecycle:
///   - board funds from an external onchain wallet onto the Ark
///   - send out-of-round Ark payments (arkoor)
///   - offboard funds to onchain addresses
///   - manage HTLCs and Lightning receives/sends
/// - VTXO management:
///   - query spendable and pending VTXOs
///   - refresh expiring or risky VTXOs
///   - compute balance broken down by spendable/pending states
/// - Synchronization and maintenance:
///   - sync against the Ark server and the onchain source
///   - reconcile pending rounds, exits, and offchain state
///   - periodic maintenance helpers (e.g., auto-register boards, refresh policies)
///
/// Construction and persistence
/// - A [Wallet] is opened or created using a mnemonic and a backend implementing [BarkPersister].
///   - [Wallet::create],
///   - [Wallet::open]
/// - Creation allows the use of an optional onchain wallet for boarding and [Exit] functionality.
///   It also initializes any internal state and connects to the [chain::ChainSource]. See
///   [onchain::OnchainWallet] for an implementation of an onchain wallet using BDK.
///   - [Wallet::create_with_onchain],
///   - [Wallet::open_with_onchain]
///
/// Example
/// ```
/// # #[cfg(any(test, doc))]
/// # async fn demo() -> anyhow::Result<()> {
/// # use std::sync::Arc;
/// # use bark::{Config, SqliteClient, Wallet};
/// # use bark::onchain::OnchainWallet;
/// # use bark::persist::BarkPersister;
/// # use bark::persist::sqlite::helpers::in_memory_db;
/// # use bip39::Mnemonic;
/// # use bitcoin::Network;
/// # let (db_path, _) = in_memory_db();
/// let network = Network::Signet;
/// let mnemonic = Mnemonic::generate(12)?;
/// let cfg = Config {
///   server_address: String::from("https://ark.signet.2nd.dev"),
///   esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
///   ..Default::default()
/// };
///
/// // You can either use the included SQLite implementation or create your own.
/// let persister = SqliteClient::open(db_path).await?;
/// let db: Arc<dyn BarkPersister> = Arc::new(persister);
///
/// // Load or create an onchain wallet if needed
/// let onchain_wallet = OnchainWallet::load_or_create(network, mnemonic.to_seed(""), db.clone()).await?;
///
/// // Create or open the Ark wallet
/// let mut wallet = Wallet::create_with_onchain(
/// 	&mnemonic,
/// 	network,
/// 	cfg.clone(),
/// 	db,
/// 	&onchain_wallet,
/// 	false,
/// ).await?;
/// // let mut wallet = Wallet::create(&mnemonic, network, cfg.clone(), db.clone(), false).await?;
/// // let mut wallet = Wallet::open(&mnemonic, db.clone(), cfg.clone()).await?;
/// // let mut wallet = Wallet::open_with_onchain(
/// //    &mnemonic, network, cfg.clone(), db.clone(), &onchain_wallet
/// // ).await?;
///
/// // There are two main ways to update the wallet, the primary is to use one of the maintenance
/// // commands which will sync everything, refresh VTXOs and reconcile pending lightning payments.
/// wallet.maintenance().await?;
/// wallet.maintenance_with_onchain(&mut onchain_wallet).await?;
///
/// // Alternatively, you can use the fine-grained sync commands to sync individual parts of the
/// // wallet state and use `maintenance_refresh` where necessary to refresh VTXOs.
/// wallet.sync().await?;
/// wallet.sync_pending_lightning_send_vtxos().await?;
/// wallet.register_all_confirmed_boards(&mut onchain_wallet).await?;
/// wallet.sync_exits(&mut onchain_wallet).await?;
/// wallet.maintenance_refresh().await?;
///
/// // Generate a new Ark address to receive funds via arkoor
/// let addr = wallet.new_address().await?;
///
/// // Query balance and VTXOs
/// let balance = wallet.balance()?;
/// let vtxos = wallet.vtxos()?;
///
/// // Progress any unilateral exits, make sure to sync first
/// wallet.exit.progress_exit(&mut onchain_wallet, None).await?;
///
/// # Ok(())
/// # }
/// ```
pub struct Wallet {
	/// The chain source the wallet is connected to
	pub chain: Arc<ChainSource>,

	/// Exit subsystem handling unilateral exits and on-chain reconciliation outside Ark rounds.
	pub exit: RwLock<Exit>,

	/// Allows easy creation of and management of wallet fund movements.
	pub movements: Arc<MovementManager>,

	/// Active runtime configuration for networking, fees, policies and thresholds.
	config: Config,

	/// Persistence backend for wallet state (keys metadata, VTXOs, movements, round state, etc.).
	db: Arc<dyn BarkPersister>,

	/// Deterministic seed material used to generate wallet keypairs.
	seed: WalletSeed,

	/// Optional live connection to an Ark server for round participation and synchronization.
	server: parking_lot::RwLock<Option<ServerConnection>>,

	/// Tracks payment hashes of lightning payments currently being processed.
	/// Used to prevent concurrent payment attempts for the same invoice.
	inflight_lightning_payments: Mutex<HashSet<PaymentHash>>,
}

impl Wallet {
	/// Creates a [chain::ChainSource] instance to communicate with an onchain backend from the
	/// given [Config].
	pub fn chain_source(
		config: &Config,
	) -> anyhow::Result<ChainSourceSpec> {
		if let Some(ref url) = config.esplora_address {
			Ok(ChainSourceSpec::Esplora {
				url: url.clone(),
			})
		} else if let Some(ref url) = config.bitcoind_address {
			let auth = if let Some(ref c) = config.bitcoind_cookiefile {
				bitcoin_ext::rpc::Auth::CookieFile(c.clone())
			} else {
				bitcoin_ext::rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			Ok(ChainSourceSpec::Bitcoind {
				url: url.clone(),
				auth,
			})
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		}
	}

	/// Verifies that the bark [Wallet] can be used with the configured [chain::ChainSource].
	/// More specifically, if the [chain::ChainSource] connects to Bitcoin Core it must be
	/// a high enough version to support ephemeral anchors.
	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.chain.require_version()
	}

	pub async fn network(&self) -> anyhow::Result<Network> {
		Ok(self.properties().await?.network)
	}

	/// Derive and store the keypair directly after currently last revealed one,
	/// together with its index.
	pub async fn derive_store_next_keypair(&self) -> anyhow::Result<(Keypair, u32)> {
		let last_revealed = self.db.get_last_vtxo_key_index().await?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(u32::MIN);
		let keypair = self.seed.derive_vtxo_keypair(index);

		self.db.store_vtxo_key(index, keypair.public_key()).await?;
		Ok((keypair, index))
	}

	/// Retrieves a keypair based on the provided index and checks if the corresponding public key
	/// exists in the [Vtxo] database.
	///
	/// # Arguments
	///
	/// * `index` - The index used to derive a keypair.
	///
	/// # Returns
	///
	/// * `Ok(Keypair)` - If the keypair is successfully derived and its public key exists in the
	///   database.
	/// * `Err(anyhow::Error)` - If the public key does not exist in the database or if an error
	///   occurs during the database query.
	pub async fn peak_keypair(&self, index: u32) -> anyhow::Result<Keypair> {
		let keypair = self.seed.derive_vtxo_keypair(index);
		if self.db.get_public_key_idx(&keypair.public_key()).await?.is_some() {
			Ok(keypair)
		} else {
			bail!("VTXO key {} does not exist, please derive it first", index)
		}
	}


	/// Retrieves the [Keypair] for a provided [PublicKey]
	///
	/// # Arguments
	///
	/// * `public_key` - The public key for which the keypair must be found
	///
	/// # Returns
	/// * `Ok(Some(u32, Keypair))` - If the pubkey is found, the derivation-index and keypair are
	///                              returned
	/// * `Ok(None)` - If the pubkey cannot be found in the database
	/// * `Err(anyhow::Error)` - If an error occurred related to the database query
	pub async fn pubkey_keypair(&self, public_key: &PublicKey) -> anyhow::Result<Option<(u32, Keypair)>> {
		if let Some(index) = self.db.get_public_key_idx(&public_key).await? {
			Ok(Some((index, self.seed.derive_vtxo_keypair(index))))
		} else {
			Ok(None)
		}
	}

	/// Retrieves the [Keypair] for a provided [Vtxo]
	///
	/// # Arguments
	///
	/// * `vtxo` - The vtxo for which the key must be found
	///
	/// # Returns
	/// * `Ok(Some(Keypair))` - If the pubkey is found, the keypair is returned
	/// * `Err(anyhow::Error)` - If the corresponding public key doesn't exist
	///   in the database or a database error occurred.
	pub async fn get_vtxo_key(&self, vtxo: impl VtxoRef) -> anyhow::Result<Keypair> {
		let vtxo = match vtxo.vtxo_ref() {
			Some(v) => v,
			None => &self.get_vtxo_by_id(vtxo.vtxo_id()).await?,
		};
		let pubkey = self.find_signable_clause(vtxo).await
			.context("VTXO is not signable by wallet")?
			.pubkey();
		let idx = self.db.get_public_key_idx(&pubkey).await?
			.context("VTXO key not found")?;
		Ok(self.seed.derive_vtxo_keypair(idx))
	}

	/// Peak for a mailbox [ark::Address] at the given key index.
	///
	/// May return an error if the address at the given index has not been derived yet.
	pub async fn peak_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		let (_, ark_info) = &self.require_server().await?;
		let network = self.properties().await?.network;
		let keypair = self.peak_keypair(index).await?;

		let mailbox_kp = self.mailbox_keypair()?;
		let mailbox = MailboxIdentifier::from_pubkey(mailbox_kp.public_key());

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark_info.server_pubkey)
			.pubkey_policy(keypair.public_key())
			.mailbox(ark_info.mailbox_pubkey, mailbox, &keypair)
			.expect("Failed to assign mailbox")
			.into_address().unwrap())
	}

	/// Generate a new [ark::Address] and returns the index of the key used to create it.
	///
	/// This derives and stores the keypair directly after currently last revealed one.
	pub async fn new_address_with_index(&self) -> anyhow::Result<(ark::Address, u32)> {
		let (_, index) = self.derive_store_next_keypair().await?;
		let addr = self.peak_address(index).await?;
		Ok((addr, index))
	}

	/// Generate a new mailbox [ark::Address].
	pub async fn new_address(&self) -> anyhow::Result<ark::Address> {
		let (addr, _) = self.new_address_with_index().await?;
		Ok(addr)
	}

	/// Create a new wallet without an optional onchain backend. This will restrict features such as
	/// boarding and unilateral exit.
	///
	/// The `force` flag will allow you to create the wallet even if a connection to the Ark server
	/// cannot be established, it will not overwrite a wallet which has already been created.
	pub async fn create(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<dyn BarkPersister>,
		force: bool,
	) -> anyhow::Result<Wallet> {
		trace!("Config: {:?}", config);
		if let Some(existing) = db.read_properties().await? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		// Try to connect to the server and get its pubkey
		let server_pubkey = if !force {
			match ServerConnection::connect(&config.server_address, network).await {
				Ok(conn) => {
					let ark_info = conn.ark_info().await?;
					Some(ark_info.server_pubkey)
				}
				Err(err) => {
					bail!("Failed to connect to provided server (if you are sure use the --force flag): {}", err);
				}
			}
		} else {
			None
		};

		let wallet_fingerprint = WalletSeed::new(network, &mnemonic.to_seed("")).fingerprint();
		let properties = WalletProperties {
			network,
			fingerprint: wallet_fingerprint,
			server_pubkey,
		};

		// write the config to db
		db.init_wallet(&properties).await.context("cannot init wallet in the database")?;
		info!("Created wallet with fingerprint: {}", wallet_fingerprint);
		if let Some(pk) = server_pubkey {
			info!("Stored server pubkey: {}", pk);
		}

		// from then on we can open the wallet
		let wallet = Wallet::open(&mnemonic, db, config).await.context("failed to open wallet")?;
		wallet.require_chainsource_version()?;

		Ok(wallet)
	}

	/// Create a new wallet with an onchain backend. This enables full Ark functionality. A default
	/// implementation of an onchain wallet when the `onchain_bdk` feature is enabled. See
	/// [onchain::OnchainWallet] for more details. Alternatively, implement [ExitUnilaterally] if
	/// you have your own onchain wallet implementation.
	///
	/// The `force` flag will allow you to create the wallet even if a connection to the Ark server
	/// cannot be established, it will not overwrite a wallet which has already been created.
	pub async fn create_with_onchain(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<dyn BarkPersister>,
		onchain: &dyn ExitUnilaterally,
		force: bool,
	) -> anyhow::Result<Wallet> {
		let mut wallet = Wallet::create(mnemonic, network, config, db, force).await?;
		wallet.exit.get_mut().load(onchain).await?;
		Ok(wallet)
	}

	/// Loads the bark wallet from the given database ensuring the fingerprint remains consistent.
	pub async fn open(
		mnemonic: &Mnemonic,
		db: Arc<dyn BarkPersister>,
		config: Config,
	) -> anyhow::Result<Wallet> {
		let properties = db.read_properties().await?.context("Wallet is not initialised")?;

		let seed = {
			let seed = mnemonic.to_seed("");
			WalletSeed::new(properties.network, &seed)
		};

		if properties.fingerprint != seed.fingerprint() {
			bail!("incorrect mnemonic")
		}

		let chain_source = if let Some(ref url) = config.esplora_address {
			ChainSourceSpec::Esplora {
				url: url.clone(),
			}
		} else if let Some(ref url) = config.bitcoind_address {
			let auth = if let Some(ref c) = config.bitcoind_cookiefile {
				bitcoin_ext::rpc::Auth::CookieFile(c.clone())
			} else {
				bitcoin_ext::rpc::Auth::UserPass(
					config.bitcoind_user.clone().context("need bitcoind auth config")?,
					config.bitcoind_pass.clone().context("need bitcoind auth config")?,
				)
			};
			ChainSourceSpec::Bitcoind { url: url.clone(), auth }
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		};

		let chain_source_client = ChainSource::new(
			chain_source, properties.network, config.fallback_fee_rate,
		).await?;
		let chain = Arc::new(chain_source_client);

		let server = match ServerConnection::connect(
			&config.server_address, properties.network,
		).await {
			Ok(s) => Some(s),
			Err(e) => {
				warn!("Ark server handshake failed: {}", e);
				None
			}
		};
		let server = parking_lot::RwLock::new(server);

		let movements = Arc::new(MovementManager::new(db.clone()));
		let exit = RwLock::new(Exit::new(db.clone(), chain.clone(), movements.clone()).await?);

		Ok(Wallet {
			config,
			db,
			seed,
			exit,
			movements,
			server,
			chain,
			inflight_lightning_payments: Mutex::new(HashSet::new()),
		})
	}

	/// Similar to [Wallet::open] however this also unilateral exits using the provided onchain
	/// wallet.
	pub async fn open_with_onchain(
		mnemonic: &Mnemonic,
		db: Arc<dyn BarkPersister>,
		onchain: &dyn ExitUnilaterally,
		cfg: Config,
	) -> anyhow::Result<Wallet> {
		let mut wallet = Wallet::open(mnemonic, db, cfg).await?;
		wallet.exit.get_mut().load(onchain).await?;
		Ok(wallet)
	}

	/// Returns the config used to create/load the bark [Wallet].
	pub fn config(&self) -> &Config {
		&self.config
	}

	/// Retrieves the [WalletProperties] of the current bark [Wallet].
	pub async fn properties(&self) -> anyhow::Result<WalletProperties> {
		let properties = self.db.read_properties().await?.context("Wallet is not initialised")?;
		Ok(properties)
	}

	/// Returns the fingerprint of the wallet.
	pub fn fingerprint(&self) -> Fingerprint {
		self.seed.fingerprint()
	}

	async fn require_server(&self) -> anyhow::Result<(ServerConnection, ArkInfo)> {
		let conn = self.server.read().clone()
			.context("You should be connected to Ark server to perform this action")?;
		let ark_info = conn.ark_info().await?;

		// Check if server pubkey has changed
		if let Some(stored_pubkey) = self.properties().await?.server_pubkey {
			if stored_pubkey != ark_info.server_pubkey {
				log_server_pubkey_changed_error(stored_pubkey, ark_info.server_pubkey);
				bail!("Server public key has changed. You should exit all your VTXOs!");
			}
		} else {
			// First time connecting after upgrade - store the server pubkey
			self.db.set_server_pubkey(ark_info.server_pubkey).await?;
			info!("Stored server pubkey for existing wallet: {}", ark_info.server_pubkey);
		}

		Ok((conn, ark_info))
	}

	pub async fn refresh_server(&self) -> anyhow::Result<()> {
		let server = self.server.read().clone();
		let properties = self.properties().await?;

		let srv = if let Some(srv) = server {
			srv.check_connection().await?;
			let ark_info = srv.ark_info().await?;
			ark_info.fees.validate().context("invalid fee schedule")?;

			// Check if server pubkey has changed
			if let Some(stored_pubkey) = properties.server_pubkey {
				if stored_pubkey != ark_info.server_pubkey {
					log_server_pubkey_changed_error(stored_pubkey, ark_info.server_pubkey);
					bail!("Server public key has changed. You should exit all your VTXOs!");
				}
			} else {
				// First time connecting after upgrade - store the server pubkey
				self.db.set_server_pubkey(ark_info.server_pubkey).await?;
				info!("Stored server pubkey for existing wallet: {}", ark_info.server_pubkey);
			}

			srv
		} else {
			let srv_address = &self.config.server_address;
			let network = properties.network;

			let conn = ServerConnection::connect(srv_address, network).await?;
			let ark_info = conn.ark_info().await?;
			ark_info.fees.validate().context("invalid fee schedule")?;

			// Check if server pubkey has changed
			if let Some(stored_pubkey) = properties.server_pubkey {
				if stored_pubkey != ark_info.server_pubkey {
					log_server_pubkey_changed_error(stored_pubkey, ark_info.server_pubkey);
					bail!("Server public key has changed. You should exit all your VTXOs!");
				}
			} else {
				// First time connecting after upgrade - store the server pubkey
				self.db.set_server_pubkey(ark_info.server_pubkey).await?;
				info!("Stored server pubkey for existing wallet: {}", ark_info.server_pubkey);
			}

			conn
		};

		let _ = self.server.write().insert(srv);

		Ok(())
	}

	/// Return [ArkInfo] fetched on last handshake with the Ark server
	pub async fn ark_info(&self) -> anyhow::Result<Option<ArkInfo>> {
		let server = self.server.read().clone();
		match server.as_ref() {
			Some(srv) => Ok(Some(srv.ark_info().await?)),
			_ => Ok(None),
		}
	}

	/// Return the [Balance] of the wallet.
	///
	/// Make sure you sync before calling this method.
	pub async fn balance(&self) -> anyhow::Result<Balance> {
		let vtxos = self.vtxos().await?;

		let spendable = {
			let mut v = vtxos.iter().collect();
			VtxoStateKind::Spendable.filter_vtxos(&mut v).await?;
			v.into_iter().map(|v| v.amount()).sum::<Amount>()
		};

		let pending_lightning_send = self.pending_lightning_send_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let claimable_lightning_receive = self.claimable_lightning_receive_balance().await?;

		let pending_board = self.pending_board_vtxos().await?.iter()
			.map(|v| v.amount())
			.sum::<Amount>();

		let pending_in_round = self.pending_round_balance().await?;

		let pending_exit = self.exit.try_read().ok().map(|e| e.pending_total());

		Ok(Balance {
			spendable,
			pending_in_round,
			pending_lightning_send,
			claimable_lightning_receive,
			pending_exit,
			pending_board,
		})
	}

	/// Fetches [Vtxo]'s funding transaction and validates the VTXO against it.
	pub async fn validate_vtxo(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let tx = self.chain.get_tx(&vtxo.chain_anchor().txid).await
			.context("could not fetch chain tx")?;

		let tx = tx.with_context(|| {
			format!("vtxo chain anchor not found for vtxo: {}", vtxo.chain_anchor().txid)
		})?;

		vtxo.validate(&tx)?;

		Ok(())
	}

	/// Manually import a VTXO into the wallet.
	///
	/// # Arguments
	/// * `vtxo` - The VTXO to import
	///
	/// # Errors
	/// Returns an error if:
	/// - The VTXO's chain anchor is not found or invalid
	/// - The wallet doesn't own a signable clause for the VTXO
	pub async fn import_vtxo(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		if self.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
			info!("VTXO {} already exists in wallet, skipping import", vtxo.id());
			return Ok(());
		}

		self.validate_vtxo(vtxo).await.context("VTXO validation failed")?;

		if self.find_signable_clause(vtxo).await.is_none() {
			bail!("VTXO {} is not owned by this wallet (no signable clause found)", vtxo.id());
		}

		let current_height = self.chain.tip().await?;
		if vtxo.expiry_height() <= current_height {
			bail!("Vtxo {} has expired", vtxo.id());
		}

		self.store_spendable_vtxos([vtxo]).await.context("failed to store imported VTXO")?;

		info!("Successfully imported VTXO {}", vtxo.id());
		Ok(())
	}

	/// Retrieves the full state of a [Vtxo] for a given [VtxoId] if it exists in the database.
	pub async fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<WalletVtxo> {
		let vtxo = self.db.get_wallet_vtxo(vtxo_id).await
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	/// Fetches all movements ordered from newest to oldest.
	#[deprecated(since="0.1.0-beta.5", note = "Use Wallet::history instead")]
	pub async fn movements(&self) -> anyhow::Result<Vec<Movement>> {
		self.history().await
	}

	/// Fetches all wallet fund movements ordered from newest to oldest.
	pub async fn history(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(self.db.get_all_movements().await?)
	}

	/// Returns all VTXOs from the database.
	pub async fn all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.db.get_all_vtxos().await?)
	}

	/// Returns all not spent vtxos
	pub async fn vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.db.get_vtxos_by_state(&VtxoStateKind::UNSPENT_STATES).await?)
	}

	/// Returns all vtxos matching the provided predicate
	pub async fn vtxos_with(&self, filter: &impl FilterVtxos) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.vtxos().await?;
		filter.filter_vtxos(&mut vtxos).await.context("error filtering vtxos")?;
		Ok(vtxos)
	}

	/// Returns all spendable vtxos
	pub async fn spendable_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.vtxos_with(&VtxoStateKind::Spendable).await?)
	}

	/// Returns all spendable vtxos matching the provided predicate
	pub async fn spendable_vtxos_with(
		&self,
		filter: &impl FilterVtxos,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.spendable_vtxos().await?;
		filter.filter_vtxos(&mut vtxos).await.context("error filtering vtxos")?;
		Ok(vtxos)
	}

	/// Returns all vtxos that will expire within `threshold` blocks
	pub async fn get_expiring_vtxos(
		&self,
		threshold: BlockHeight,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let expiry = self.chain.tip().await? + threshold;
		let filter = VtxoFilter::new(&self).expires_before(expiry);
		Ok(self.spendable_vtxos_with(&filter).await?)
	}

	/// Performs maintenance tasks and performs refresh interactively until finished when needed.
	/// This risks spending users' funds because refreshing may cost fees.
	///
	/// This can take a long period of time due to syncing rounds, arkoors, checking pending
	/// payments, progressing pending rounds, and refreshing VTXOs if necessary.
	pub async fn maintenance(&self) -> anyhow::Result<()> {
		info!("Starting wallet maintenance in interactive mode");
		self.sync().await;

		let rounds = self.progress_pending_rounds(None).await;
		if let Err(e) = rounds.as_ref() {
			warn!("Error progressing pending rounds: {:#}", e);
		}
		let refresh = self.maintenance_refresh().await;
		if let Err(e) = refresh.as_ref() {
			warn!("Error refreshing VTXOs: {:#}", e);
		}
		if rounds.is_err() || refresh.is_err() {
			bail!("Maintenance encountered errors.\nprogress_rounds: {:#?}\nrefresh: {:#?}", rounds, refresh);
		}
		Ok(())
	}

	/// Performs maintenance tasks and schedules delegated refresh when needed. This risks spending
	/// users' funds because refreshing may cost fees.
	///
	/// This can take a long period of time due to syncing rounds, arkoors, checking pending
	/// payments, progressing pending rounds, and refreshing VTXOs if necessary.
	pub async fn maintenance_delegated(&self) -> anyhow::Result<()> {
		info!("Starting wallet maintenance in delegated mode");
		self.sync().await;
		let rounds = self.progress_pending_rounds(None).await;
		if let Err(e) = rounds.as_ref() {
			warn!("Error progressing pending rounds: {:#}", e);
		}
		let refresh = self.maybe_schedule_maintenance_refresh_delegated().await;
		if let Err(e) = refresh.as_ref() {
			warn!("Error refreshing VTXOs: {:#}", e);
		}
		if rounds.is_err() || refresh.is_err() {
			bail!("Delegated maintenance encountered errors.\nprogress_rounds: {:#?}\nrefresh: {:#?}", rounds, refresh);
		}
		Ok(())
	}

	/// Performs maintenance tasks and performs refresh interactively until finished when needed.
	/// This risks spending users' funds because refreshing may cost fees and any pending exits will
	/// be progressed.
	///
	/// This can take a long period of time due to syncing the onchain wallet, registering boards,
	/// syncing rounds, arkoors, and the exit system, checking pending lightning payments and
	/// refreshing VTXOs if necessary.
	pub async fn maintenance_with_onchain<W: PreparePsbt + SignPsbt + ExitUnilaterally>(
		&self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		info!("Starting wallet maintenance in interactive mode with onchain wallet");

		// Maintenance will log so we don't need to.
		let maintenance = self.maintenance().await;

		// NB: order matters here, after syncing lightning, we might have new exits to start
		let exit_sync = self.sync_exits(onchain).await;
		if let Err(e) = exit_sync.as_ref() {
			warn!("Error syncing exits: {:#}", e);
		}
		let exit_progress = self.exit.write().await.progress_exits(&self, onchain, None).await;
		if let Err(e) = exit_progress.as_ref() {
			warn!("Error progressing exits: {:#}", e);
		}
		if maintenance.is_err() || exit_sync.is_err() || exit_progress.is_err() {
			bail!("Maintenance encountered errors.\nmaintenance: {:#?}\nexit_sync: {:#?}\nexit_progress: {:#?}", maintenance, exit_sync, exit_progress);
		}
		Ok(())
	}

	/// Performs maintenance tasks and schedules delegated refresh when needed. This risks spending
	/// users' funds because refreshing may cost fees and any pending exits will be progressed.
	///
	/// This can take a long period of time due to syncing the onchain wallet, registering boards,
	/// syncing rounds, arkoors, and the exit system, checking pending lightning payments and
	/// refreshing VTXOs if necessary.
	pub async fn maintenance_with_onchain_delegated<W: PreparePsbt + SignPsbt + ExitUnilaterally>(
		&self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		info!("Starting wallet maintenance in delegated mode with onchain wallet");

		// Maintenance will log so we don't need to.
		let maintenance = self.maintenance_delegated().await;

		// NB: order matters here, after syncing lightning, we might have new exits to start
		let exit_sync = self.sync_exits(onchain).await;
		if let Err(e) = exit_sync.as_ref() {
			warn!("Error syncing exits: {:#}", e);
		}
		let exit_progress = self.exit.write().await.progress_exits(&self, onchain, None).await;
		if let Err(e) = exit_progress.as_ref() {
			warn!("Error progressing exits: {:#}", e);
		}
		if maintenance.is_err() || exit_sync.is_err() || exit_progress.is_err() {
			bail!("Delegated maintenance encountered errors.\nmaintenance: {:#?}\nexit_sync: {:#?}\nexit_progress: {:#?}", maintenance, exit_sync, exit_progress);
		}
		Ok(())
	}

	/// Checks VTXOs that are due to be refreshed, and schedules an interactive refresh if any
	///
	/// This will include any VTXOs within the expiry threshold
	/// ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundStateId] if a refresh is scheduled.
	pub async fn maybe_schedule_maintenance_refresh(&self) -> anyhow::Result<Option<RoundStateId>> {
		let vtxos = self.get_vtxos_to_refresh().await?;
		if vtxos.len() == 0 {
			return Ok(None);
		}

		let participation = match self.build_refresh_participation(vtxos).await? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		info!("Scheduling maintenance refresh ({} vtxos)", participation.inputs.len());
		let state = self.join_next_round(participation, Some(RoundMovement::Refresh)).await?;
		Ok(Some(state.id))
	}

	/// Checks VTXOs that are due to be refreshed, and schedules a delegated refresh if any
	///
	/// This will include any VTXOs within the expiry threshold
	/// ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundStateId] if a refresh is scheduled.
	pub async fn maybe_schedule_maintenance_refresh_delegated(
		&self,
	) -> anyhow::Result<Option<RoundStateId>> {
		let vtxos = self.get_vtxos_to_refresh().await?;
		if vtxos.len() == 0 {
			return Ok(None);
		}

		let participation = match self.build_refresh_participation(vtxos).await? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		info!("Scheduling delegated maintenance refresh ({} vtxos)", participation.inputs.len());
		let state = self.join_next_round_delegated(participation, Some(RoundMovement::Refresh)).await?;
		Ok(Some(state.id))
	}

	/// Performs an interactive refresh of all VTXOs that are due to be refreshed, if any
	///
	/// This will include any VTXOs within the expiry threshold
	/// ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundStatus] if a refresh occurs.
	pub async fn maintenance_refresh(&self) -> anyhow::Result<Option<RoundStatus>> {
		let vtxos = self.get_vtxos_to_refresh().await?;
		if vtxos.len() == 0 {
			return Ok(None);
		}

		info!("Performing maintenance refresh");
		self.refresh_vtxos(vtxos).await
	}

	/// Sync offchain wallet and update onchain fees. This is a much more lightweight alternative
	/// to [Wallet::maintenance] as it will not refresh VTXOs or sync the onchain wallet.
	///
	/// Notes:
	/// - The exit system will not be synced as doing so requires the onchain wallet.
	pub async fn sync(&self) {
		tokio::join!(
			async {
				// NB: order matters here, if syncing call fails,
				// we still want to update the fee rates
				if let Err(e) = self.chain.update_fee_rates(self.config.fallback_fee_rate).await {
					warn!("Error updating fee rates: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.sync_mailbox().await {
					warn!("Error in mailbox sync: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.sync_pending_rounds().await {
					warn!("Error while trying to progress rounds awaiting confirmations: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.sync_pending_lightning_send_vtxos().await {
					warn!("Error syncing pending lightning payments: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.try_claim_all_lightning_receives(false).await {
					warn!("Error claiming pending lightning receives: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.sync_pending_boards().await {
					warn!("Error syncing pending boards: {:#}", e);
				}
			}
		);
	}

	/// Sync the transaction status of unilateral exits
	///
	/// This will not progress the unilateral exits in any way, it will merely check the
	/// transaction status of each transaction as well as check whether any exits have become
	/// claimable or have been claimed.
	pub async fn sync_exits(
		&self,
		onchain: &mut dyn ExitUnilaterally,
	) -> anyhow::Result<()> {
		self.exit.write().await.sync(&self, onchain).await?;
		Ok(())
	}

	/// Drop a specific [Vtxo] from the database. This is destructive and will result in a loss of
	/// funds.
	pub async fn dangerous_drop_vtxo(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		warn!("Drop vtxo {} from the database", vtxo_id);
		self.db.remove_vtxo(vtxo_id).await?;
		Ok(())
	}

	/// Drop all VTXOs from the database. This is destructive and will result in a loss of funds.
	//TODO(stevenroose) improve the way we expose dangerous methods
	pub async fn dangerous_drop_all_vtxos(&self) -> anyhow::Result<()> {
		warn!("Dropping all vtxos from the db...");
		for vtxo in self.vtxos().await? {
			self.db.remove_vtxo(vtxo.id()).await?;
		}

		self.exit.write().await.dangerous_clear_exit().await?;
		Ok(())
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet
	///
	/// An arkoor vtxo is considered to have some counterparty risk
	/// if it is (directly or not) based on round VTXOs that aren't owned by the wallet
	async fn has_counterparty_risk(&self, vtxo: &Vtxo) -> anyhow::Result<bool> {
		for past_pks in vtxo.past_arkoor_pubkeys() {
			let mut owns_any = false;
			for past_pk in past_pks {
				if self.db.get_public_key_idx(&past_pk).await?.is_some() {
					owns_any = true;
					break;
				}
			}
			if !owns_any {
				return Ok(true);
			}
		}

		let my_clause = self.find_signable_clause(vtxo).await;
		Ok(!my_clause.is_some())
	}

	/// If there are any VTXOs that match the "must-refresh" and "should-refresh" criteria with a
	/// total value over the P2TR dust limit, they are added to the round participation and an
	/// additional output is also created.
	///
	/// Note: This assumes that the base refresh fee has already been paid.
	async fn add_should_refresh_vtxos(
		&self,
		participation: &mut RoundParticipation,
	) -> anyhow::Result<()> {
		let excluded_ids = participation.inputs.iter().map(|v| v.vtxo_id())
			.collect::<HashSet<_>>();

		// Get VTXOs that need and should be refreshed, then filter out any duplicates before
		// adjusting the round participation.
		let tip = self.chain.tip().await?;
		let mut vtxos_to_refresh = self.spendable_vtxos_with(
			&RefreshStrategy::should_refresh(self, tip, self.chain.fee_rates().await.fast),
		).await?;
		let mut total_amount = Amount::ZERO;
		for i in (0..vtxos_to_refresh.len()).rev() {
			let vtxo = &vtxos_to_refresh[i];
			if excluded_ids.contains(&vtxo.id()) {
				vtxos_to_refresh.swap_remove(i);
				continue;
			}
			total_amount += vtxo.amount();
		}

		// We need to verify that the output we add won't end up below the dust limit when fees are
		// applied. We can assume the base fee has been paid by the current refresh participation.
		let (_, ark_info) = self.require_server().await?;
		let fee = ark_info.fees.refresh.calculate_no_base_fee(
			vtxos_to_refresh.iter().map(|wv| VtxoFeeInfo::from_vtxo_and_tip(&wv.vtxo, tip)),
		).context("fee overflowed")?;

		// Finally, ensure the output is more than dust.
		let output_amount = validate_and_subtract_fee_min_dust(total_amount, fee)?;
		if output_amount >= P2TR_DUST {
			info!(
				"Adding {} extra VTXOs to round participation total = {}, fee = {}, output = {}",
				vtxos_to_refresh.len(), total_amount, fee, output_amount,
			);
			let (user_keypair, _) = self.derive_store_next_keypair().await?;
			let req = VtxoRequest {
				policy: VtxoPolicy::new_pubkey(user_keypair.public_key()),
				amount: output_amount,
			};
			participation.inputs.reserve(vtxos_to_refresh.len());
			participation.inputs.extend(vtxos_to_refresh.into_iter().map(|wv| wv.vtxo));
			participation.outputs.push(req);
		}

		Ok(())
	}

	pub async fn build_refresh_participation<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<RoundParticipation>> {
		let (vtxos, total_amount) = {
			let iter = vtxos.into_iter();
			let size_hint = iter.size_hint();
			let mut vtxos = Vec::<Vtxo>::with_capacity(size_hint.1.unwrap_or(size_hint.0));
			let mut amount = Amount::ZERO;
			for vref in iter {
				// We use a Vec here instead of a HashMap or a HashSet of IDs because for the kinds
				// of elements we expect to deal with, a Vec is likely to be quicker. The overhead
				// of hashing each ID and making additional allocations isn't likely to be worth it
				// for what is likely to be a handful of VTXOs or at most a couple of hundred.
				let id = vref.vtxo_id();
				if vtxos.iter().any(|v| v.id() == id) {
					bail!("duplicate VTXO id: {}", id);
				}
				let vtxo = if let Some(vtxo) = vref.into_vtxo() {
					vtxo
				} else {
					self.get_vtxo_by_id(id).await
						.with_context(|| format!("vtxo with id {} not found", id))?.vtxo
				};
				amount += vtxo.amount();
				vtxos.push(vtxo);
			}
			(vtxos, amount)
		};

		if vtxos.is_empty() {
			info!("Skipping refresh since no VTXOs are provided.");
			return Ok(None);
		}
		ensure!(total_amount >= P2TR_DUST,
			"vtxo amount must be at least {} to participate in a round",
			P2TR_DUST,
		);

		// Calculate refresh fees
		let (_, ark_info) = self.require_server().await?;
		let current_height = self.chain.tip().await?;
		let vtxo_fee_infos = vtxos.iter()
			.map(|v| VtxoFeeInfo::from_vtxo_and_tip(v, current_height));
		let fee = ark_info.fees.refresh.calculate(vtxo_fee_infos).context("fee overflowed")?;
		let output_amount = validate_and_subtract_fee_min_dust(total_amount, fee)?;

		info!("Refreshing {} VTXOs (total amount = {}, fee = {}, output = {}).",
			vtxos.len(), total_amount, fee, output_amount,
		);
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		let req = VtxoRequest {
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: user_keypair.public_key() }),
			amount: output_amount,
		};

		Ok(Some(RoundParticipation {
			inputs: vtxos,
			outputs: vec![req],
		}))
	}

	/// This will refresh all provided VTXOs in an interactive round and wait until end
	///
	/// Returns the [RoundStatus] of the round if a successful refresh occurred.
	/// It will return [None] if no [Vtxo] needed to be refreshed.
	pub async fn refresh_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<RoundStatus>> {
		let mut participation = match self.build_refresh_participation(vtxos).await? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		if let Err(e) = self.add_should_refresh_vtxos(&mut participation).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(Some(self.participate_round(participation, Some(RoundMovement::Refresh)).await?))
	}

	/// This will refresh all provided VTXOs in delegated (non-interactive) mode
	///
	/// Returns the [StoredRoundState] which can be used to track the round's
	/// progress later by calling sync. It will return [None] if no [Vtxo]
	/// needed to be refreshed.
	pub async fn refresh_vtxos_delegated<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<StoredRoundState>> {
		let mut part = match self.build_refresh_participation(vtxos).await? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		if let Err(e) = self.add_should_refresh_vtxos(&mut part).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(Some(self.join_next_round_delegated(part, Some(RoundMovement::Refresh)).await?))
	}

	/// This will find all VTXOs that meets must-refresh criteria. Then, if there are some VTXOs to
	/// refresh, it will also add those that meet should-refresh criteria.
	pub async fn get_vtxos_to_refresh(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxos = self.spendable_vtxos_with(&RefreshStrategy::should_refresh_if_must(
			self,
			self.chain.tip().await?,
			self.chain.fee_rates().await.fast,
		)).await?;
		Ok(vtxos)
	}

	/// Returns the block height at which the first VTXO will expire
	pub async fn get_first_expiring_vtxo_blockheight(
		&self,
	) -> anyhow::Result<Option<BlockHeight>> {
		Ok(self.spendable_vtxos().await?.iter().map(|v| v.expiry_height()).min())
	}

	/// Returns the next block height at which we have a VTXO that we
	/// want to refresh
	pub async fn get_next_required_refresh_blockheight(
		&self,
	) -> anyhow::Result<Option<BlockHeight>> {
		let first_expiry = self.get_first_expiring_vtxo_blockheight().await?;
		Ok(first_expiry.map(|h| h.saturating_sub(self.config.vtxo_refresh_expiry_threshold)))
	}

	/// Select several VTXOs to cover the provided amount
	///
	/// VTXOs are selected soonest-expiring-first.
	///
	/// Returns an error if amount cannot be reached.
	async fn select_vtxos_to_cover(
		&self,
		amount: Amount,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.spendable_vtxos().await?;
		vtxos.sort_by_key(|v| v.expiry_height());

		// Iterate over VTXOs until the required amount is reached
		let mut result = Vec::new();
		let mut total_amount = Amount::ZERO;
		for input in vtxos {
			total_amount += input.amount();
			result.push(input);

			if total_amount >= amount {
				return Ok(result)
			}
		}

		bail!("Insufficient money available. Needed {} but {} is available",
			amount, total_amount,
		);
	}

	/// Determines which VTXOs to use for a fee-paying transaction where the fee is added on top of
	/// the desired amount. E.g., a lightning payment, a send-onchain payment.
	///
	/// Returns a collection of VTXOs capable of covering the desired amount as well as the
	/// calculated fee.
	async fn select_vtxos_to_cover_with_fee<F>(
		&self,
		amount: Amount,
		calc_fee: F,
	) -> anyhow::Result<(Vec<WalletVtxo>, Amount)>
	where
		F: for<'a> Fn(
			Amount, std::iter::Copied<std::slice::Iter<'a, VtxoFeeInfo>>,
		) -> anyhow::Result<Amount>,
	{
		let tip = self.chain.tip().await?;

		// We need to loop to find suitable inputs due to the VTXOs having a direct impact on
		// how much we must pay in fees.
		const MAX_ITERATIONS: usize = 100;
		let mut fee = Amount::ZERO;
		let mut fee_info = Vec::new();
		for _ in 0..MAX_ITERATIONS {
			let required = amount.checked_add(fee)
				.context("Amount + fee overflow")?;

			let vtxos = self.select_vtxos_to_cover(required).await
				.context("Could not find enough suitable VTXOs to cover payment + fees")?;

			fee_info.reserve(vtxos.len());
			let mut vtxo_amount = Amount::ZERO;
			for vtxo in &vtxos {
				vtxo_amount += vtxo.amount();
				fee_info.push(VtxoFeeInfo::from_vtxo_and_tip(vtxo, tip));
			}

			fee = calc_fee(amount, fee_info.iter().copied())?;
			if amount + fee <= vtxo_amount {
				trace!("Selected vtxos to cover amount + fee: amount = {}, fee = {}, total inputs = {}",
					amount, fee, vtxo_amount,
				);
				return Ok((vtxos, fee));
			}
			trace!("VTXO sum of {} did not exceed amount {} and fee {}, iterating again",
				vtxo_amount, amount, fee,
			);
			fee_info.clear();
		}
		bail!("Fee calculation did not converge after maximum iterations")
	}

	/// Starts a daemon for the wallet.
	///
	/// Note:
	/// - This function doesn't check if a daemon is already running,
	/// so it's possible to start multiple daemons by mistake.
	pub async fn run_daemon(
		self: &Arc<Self>,
		onchain: Arc<RwLock<dyn DaemonizableOnchainWallet>>,
	) -> anyhow::Result<DaemonHandle> {
		// NB currently can't error but it's a pretty common method and quite likely that error
		// cases will be introduces later
		Ok(crate::daemon::start_daemon(self.clone(), onchain))
	}

	/// Registers VTXOs with the server by sending their signed transaction chains.
	/// This should be called before spending VTXOs to ensure the server can
	/// publish forfeits if needed.
	pub async fn register_vtxos_with_server(&self, vtxos: &[impl AsRef<Vtxo>]) -> anyhow::Result<()> {
		if vtxos.is_empty() {
			return Ok(());
		}

		let (mut srv, _) = self.require_server().await?;
		srv.client.register_vtxos(protos::RegisterVtxosRequest {
			vtxos: vtxos.iter().map(|v| v.as_ref().serialize()).collect(),
		}).await.context("failed to register vtxos")?;

		Ok(())
	}
}
