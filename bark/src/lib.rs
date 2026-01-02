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
//! The user can select an Ark server and a [onchain::ChainSource] as part of
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
//! 	let vtxos: Vec<bark::WalletVtxo> = wallet.vtxos().unwrap();
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
//! use bark::vtxo::selection::RefreshStrategy;
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
//! 	let vtxos = wallet.spendable_vtxos_with(&strategy)?
//! 		.into_iter().map(|v| v.vtxo).collect::<Vec<_>>();
//!		wallet.refresh_vtxos(vtxos).await?;
//! 	Ok(())
//! }
//! ```



pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate serde;

pub mod arkoor;
pub mod daemon;
pub mod exit;
pub mod lightning;
pub mod movement;
pub mod onchain;
pub mod persist;
pub mod round;
pub mod subsystem;
pub mod vtxo;

pub use self::config::{BarkNetwork, Config};
pub use self::persist::sqlite::SqliteClient;
pub use self::vtxo::state::WalletVtxo;

mod config;
mod psbtext;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf};
use bitcoin::bip32::{self, Fingerprint};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use log::{trace, debug, info, warn, error};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

use ark::{ArkInfo, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::address::VtxoDelivery;
use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::vtxo::VtxoRef;
use ark::vtxo::policy::PubkeyVtxoPolicy;
use bitcoin_ext::{BlockHeight, P2TR_DUST, TxStatus};
use server_rpc::{self as rpc, protos, ServerConnection};

use crate::daemon::{Daemon, DaemonizableOnchainWallet};
use crate::exit::Exit;
use crate::movement::{Movement, MovementStatus};
use crate::movement::manager::MovementManager;
use crate::movement::update::MovementUpdate;
use crate::onchain::{ChainSource, PreparePsbt, ExitUnilaterally, Utxo, SignPsbt};
use crate::persist::{BarkPersister, RoundStateId};
use crate::persist::models::{LightningReceive, LightningSend, PendingBoard};
use crate::round::{RoundParticipation, RoundStatus};
use crate::subsystem::{ArkoorMovement, BarkSubsystem, BoardMovement, RoundMovement, SubsystemId};
use crate::vtxo::selection::{FilterVtxos, VtxoFilter, RefreshStrategy};
use crate::vtxo::state::{VtxoState, VtxoStateKind, UNSPENT_STATES};

const ARK_PURPOSE_INDEX: u32 = 350;

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
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
}

/// Struct representing an extended private key derived from a
/// wallet's seed, used to derive child VTXO keypairs
///
/// The VTXO seed is derived by applying a hardened derivation
/// step at index 350 from the wallet's seed.
pub struct VtxoSeed(bip32::Xpriv);

impl VtxoSeed {
	fn new(network: Network, seed: &[u8; 64]) -> Self {
		let master = bip32::Xpriv::new_master(network, seed).unwrap();

		Self(master.derive_priv(&SECP, &[ARK_PURPOSE_INDEX.into()]).unwrap())
	}

	fn fingerprint(&self) -> Fingerprint {
		self.0.fingerprint(&SECP)
	}

	fn derive_keypair(&self, idx: u32) -> Keypair {
		self.0.derive_priv(&SECP, &[idx.into()]).unwrap().to_keypair(&SECP)
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
///     - [Wallet::send_round_onchain_payment],
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
///   It also initializes any internal state and connects to the [onchain::ChainSource]. See
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
/// let onchain_wallet = OnchainWallet::load_or_create(network, mnemonic.to_seed(""), db.clone())?;
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

	/// Deterministic seed material used to derive VTXO ownership keypairs and addresses.
	vtxo_seed: VtxoSeed,

	/// Optional live connection to an Ark server for round participation and synchronization.
	server: parking_lot::RwLock<Option<ServerConnection>>,

	/// TODO: Replace this when we move to a modular subsystem architecture
	subsystem_ids: HashMap<BarkSubsystem, SubsystemId>,
}

impl Wallet {
	/// Creates a [onchain::ChainSource] instance to communicate with an onchain backend from the
	/// given [Config].
	pub fn chain_source(
		config: &Config,
	) -> anyhow::Result<onchain::ChainSourceSpec> {
		if let Some(ref url) = config.esplora_address {
			Ok(onchain::ChainSourceSpec::Esplora {
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
			Ok(onchain::ChainSourceSpec::Bitcoind {
				url: url.clone(),
				auth,
			})
		} else {
			bail!("Need to either provide esplora or bitcoind info");
		}
	}

	/// Verifies that the bark [Wallet] can be used with the configured [onchain::ChainSource].
	/// More specifically, if the [onchain::ChainSource] connects to Bitcoin Core it must be
	/// a high enough version to support ephemeral anchors.
	pub fn require_chainsource_version(&self) -> anyhow::Result<()> {
		self.chain.require_version()
	}

	/// Derive and store the keypair directly after currently last revealed one,
	/// together with its index.
	pub fn derive_store_next_keypair(&self) -> anyhow::Result<(Keypair, u32)> {
		let last_revealed = self.db.get_last_vtxo_key_index()?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(u32::MIN);
		let keypair = self.vtxo_seed.derive_keypair(index);

		self.db.store_vtxo_key(index, keypair.public_key())?;
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
	pub fn peak_keypair(&self, index: u32) -> anyhow::Result<Keypair> {
		let keypair = self.vtxo_seed.derive_keypair(index);
		if self.db.get_public_key_idx(&keypair.public_key())?.is_some() {
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
	pub fn pubkey_keypair(&self, public_key: &PublicKey) -> anyhow::Result<Option<(u32, Keypair)>> {
		if let Some(index) = self.db.get_public_key_idx(&public_key)? {
			Ok(Some((index, self.vtxo_seed.derive_keypair(index))))
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
	pub fn get_vtxo_key(&self, vtxo: &Vtxo) -> anyhow::Result<Keypair> {
		let idx = self.db.get_public_key_idx(&vtxo.user_pubkey())?
			.context("VTXO key not found")?;
		Ok(self.vtxo_seed.derive_keypair(idx))
	}

	/// Generate a new [ark::Address].
	pub async fn new_address(&self) -> anyhow::Result<ark::Address> {
		let srv = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.derive_store_next_keypair()?.0.public_key();

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(srv.ark_info().await?.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Peak for an [ark::Address] at the given key index.
	///
	/// May return an error if the address at the given index has not been derived yet.
	pub async fn peak_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		let srv = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.peak_keypair(index)?.public_key();

		Ok(ark::Address::builder()
			.testnet(network != Network::Bitcoin)
			.server_pubkey(srv.ark_info().await?.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Generate a new [ark::Address] and returns the index of the key used to create it.
	///
	/// This derives and stores the keypair directly after currently last revealed one.
	pub async fn new_address_with_index(&self) -> anyhow::Result<(ark::Address, u32)> {
		let srv = &self.require_server()?;
		let network = self.properties()?.network;
		let (keypair, index) = self.derive_store_next_keypair()?;
		let pubkey = keypair.public_key();
		let addr = ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(srv.ark_info().await?.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address()?;
		Ok((addr, index))
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
		if let Some(existing) = db.read_properties()? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		if !force {
			if let Err(err) = ServerConnection::connect(&config.server_address, network).await {
				bail!("Failed to connect to provided server (if you are sure use the --force flag): {}", err);
			}
		}

		let wallet_fingerprint = VtxoSeed::new(network, &mnemonic.to_seed("")).fingerprint();
		let properties = WalletProperties {
			network: network,
			fingerprint: wallet_fingerprint,
		};

		// write the config to db
		db.init_wallet(&properties).context("cannot init wallet in the database")?;
		info!("Created wallet with fingerprint: {}", wallet_fingerprint);

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
		let properties = db.read_properties()?.context("Wallet is not initialised")?;

		let seed = mnemonic.to_seed("");
		let vtxo_seed = VtxoSeed::new(properties.network, &seed);

		if properties.fingerprint != vtxo_seed.fingerprint() {
			bail!("incorrect mnemonic")
		}

		let chain_source = if let Some(ref url) = config.esplora_address {
			onchain::ChainSourceSpec::Esplora {
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
			onchain::ChainSourceSpec::Bitcoind { url: url.clone(), auth }
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
		let mut subsystem_ids = HashMap::new();
		{
			let subsystems = [
				BarkSubsystem::Arkoor,
				BarkSubsystem::Board,
				BarkSubsystem::LightningReceive,
				BarkSubsystem::LightningSend,
				BarkSubsystem::Round,
			];
			for subsystem in subsystems {
				let id = movements.register_subsystem(subsystem.as_str().into()).await?;
				subsystem_ids.insert(subsystem, id);
			}
		};

		Ok(Wallet { config, db, vtxo_seed, exit, movements, server, chain, subsystem_ids })
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
	pub fn properties(&self) -> anyhow::Result<WalletProperties> {
		let properties = self.db.read_properties()?.context("Wallet is not initialised")?;
		Ok(properties)
	}

	fn require_server(&self) -> anyhow::Result<ServerConnection> {
		self.server.read().clone()
			.context("You should be connected to Ark server to perform this action")
	}

	pub async fn refresh_server(&self) -> anyhow::Result<()> {
		let server = self.server.read().clone();

		let srv = if let Some(srv) = server {
			srv.check_connection().await?;
			srv.ark_info().await?;
			srv
		} else {
			let srv_address = &self.config.server_address;
			let network = self.properties()?.network;

			ServerConnection::connect(srv_address, network).await?
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
	pub fn balance(&self) -> anyhow::Result<Balance> {
		let vtxos = self.vtxos()?;

		let spendable = {
			let mut v = vtxos.iter().collect();
			VtxoStateKind::Spendable.filter_vtxos(&mut v)?;
			v.into_iter().map(|v| v.amount()).sum::<Amount>()
		};

		let pending_lightning_send = self.pending_lightning_send_vtxos()?.iter().map(|v| v.amount())
			.sum::<Amount>();

		let claimable_lightning_receive = self.claimable_lightning_receive_balance()?;

		let pending_board = self.pending_board_vtxos()?.iter().map(|v| v.amount()).sum::<Amount>();

		let pending_in_round = self.pending_round_input_vtxos()?.iter().map(|v| v.amount()).sum();

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

	/// Retrieves the full state of a [Vtxo] for a given [VtxoId] if it exists in the database.
	pub fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<WalletVtxo> {
		let vtxo = self.db.get_wallet_vtxo(vtxo_id)
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	/// Fetches all movements ordered from newest to oldest.
	#[deprecated(since="0.1.0-beta.5", note = "Use Wallet::history instead")]
	pub fn movements(&self) -> anyhow::Result<Vec<Movement>> {
		self.history()
	}

	/// Fetches all wallet fund movements ordered from newest to oldest.
	pub fn history(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(self.db.get_all_movements()?)
	}

	/// Returns all VTXOs from the database.
	pub fn all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.db.get_all_vtxos()?)
	}

	/// Returns all not spent vtxos
	pub fn vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.db.get_vtxos_by_state(&UNSPENT_STATES)?)
	}

	/// Returns all vtxos matching the provided predicate
	pub fn vtxos_with(&self, filter: &impl FilterVtxos) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.vtxos()?;
		filter.filter_vtxos(&mut vtxos).context("error filtering vtxos")?;
		Ok(vtxos)
	}

	/// Returns all spendable vtxos
	pub fn spendable_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.vtxos_with(&VtxoStateKind::Spendable)?)
	}

	/// Returns all spendable vtxos matching the provided predicate
	pub fn spendable_vtxos_with(
		&self,
		filter: &impl FilterVtxos,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.spendable_vtxos()?;
		filter.filter_vtxos(&mut vtxos).context("error filtering vtxos")?;
		Ok(vtxos)
	}

	pub fn pending_boards(&self) -> anyhow::Result<Vec<PendingBoard>> {
		let boarding_vtxo_ids = self.db.get_all_pending_board_ids()?;
		let mut boards = Vec::with_capacity(boarding_vtxo_ids.len());
		for vtxo_id in boarding_vtxo_ids {
			let board = self.db.get_pending_board_by_vtxo_id(vtxo_id)?
				.expect("id just retrieved from db");
			boards.push(board);
		}
		Ok(boards)
	}

	/// Queries the database for any VTXO that is an unregistered board. There is a lag time between
	/// when a board is created and when it becomes spendable.
	///
	/// See [ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxo_ids = self.pending_boards()?.into_iter()
			.flat_map(|b| b.vtxos.into_iter())
			.collect::<Vec<_>>();

		let mut vtxos = Vec::with_capacity(vtxo_ids.len());
		for vtxo_id in vtxo_ids {
			let vtxo = self.get_vtxo_by_id(vtxo_id)
				.expect("vtxo id just got retrieved from db");
			vtxos.push(vtxo);
		}

		debug_assert!(vtxos.iter().all(|v| matches!(v.state.kind(), VtxoStateKind::Locked)),
			"all pending board vtxos should be locked"
		);

		Ok(vtxos)
	}

	/// Returns all VTXOs that are locked in a pending round
	///
	/// This excludes all input VTXOs for which the output VTXOs have already
	/// been created.
	pub fn pending_round_input_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut ret = Vec::new();
		for round in self.db.load_round_states()? {
			let inputs = round.state.locked_pending_inputs();
			ret.reserve(inputs.len());
			for input in inputs {
				ret.push(self.get_vtxo_by_id(input.id()).context("unknown round input VTXO")?);
			}
		}
		Ok(ret)
	}

	/// Queries the database for any VTXO that is a pending lightning send.
	pub fn pending_lightning_send_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxos = self.db.get_all_pending_lightning_send()?.into_iter()
			.flat_map(|pending_lightning_send| pending_lightning_send.htlc_vtxos)
			.collect::<Vec<_>>();

		Ok(vtxos)
	}

	/// Returns all vtxos that will expire within `threshold` blocks
	pub async fn get_expiring_vtxos(
		&self,
		threshold: BlockHeight,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let expiry = self.chain.tip().await? + threshold;
		let filter = VtxoFilter::new(&self).expires_before(expiry);
		Ok(self.spendable_vtxos_with(&filter)?)
	}

	/// Attempts to register all pendings boards with the Ark server. A board transaction must have
	/// sufficient confirmations before it will be registered. For more details see
	/// [ArkInfo::required_board_confirmations].
	pub async fn sync_pending_boards(&self) -> anyhow::Result<()> {
		let ark_info = self.require_server()?.ark_info().await?;
		let current_height = self.chain.tip().await?;
		let unregistered_boards = self.pending_boards()?;
		let mut registered_boards = 0;

		if unregistered_boards.is_empty() {
			return Ok(());
		}

		trace!("Attempting registration of sufficiently confirmed boards");

		for board in unregistered_boards {
			let [vtxo_id] = board.vtxos.try_into()
				.map_err(|_| anyhow!("multiple board vtxos is not supported yet"))?;

			let vtxo = self.get_vtxo_by_id(vtxo_id)?;

			let anchor = vtxo.chain_anchor();
			let confs = match self.chain.tx_status(anchor.txid).await {
				Ok(TxStatus::Confirmed(block_ref)) => Some(current_height - (block_ref.height - 1)),
				Ok(TxStatus::Mempool) => Some(0),
				Ok(TxStatus::NotFound) => None,
				Err(_) => None,
			};

			if let Some(confs) = confs {
				if confs >= ark_info.required_board_confirmations as BlockHeight {
					if let Err(e) = self.register_board(vtxo.id()).await {
						warn!("Failed to register board {}: {}", vtxo.id(), e);
					} else {
						info!("Registered board {}", vtxo.id());
						registered_boards += 1;
					}
				}

				continue;
			}

			if vtxo.expiry_height() < current_height + ark_info.required_board_confirmations as BlockHeight {
				warn!("VTXO {} expired before its board was confirmed, removing board", vtxo.id());
				self.movements.finish_movement(board.movement_id, MovementStatus::Failed).await?;
				self.mark_vtxos_as_spent(&[vtxo])?;
				self.db.remove_pending_board(&vtxo_id)?;
			}
		};

		if registered_boards > 0 {
			info!("Registered {registered_boards} sufficiently confirmed boards");
		}
		Ok(())
	}

	/// Performs maintenance tasks on the offchain wallet.
	///
	/// This can take a long period of time due to syncing rounds, arkoors, checking pending
	/// payments, progressing pending rounds, and refreshing VTXOs if necessary.
	pub async fn maintenance(&self) -> anyhow::Result<()> {
		info!("Starting wallet maintenance");
		self.sync().await;
		self.progress_pending_rounds(None).await?;
		self.maintenance_refresh().await?;
		Ok(())
	}

	/// Performs maintenance tasks on the onchain and offchain wallet.
	///
	/// This can take a long period of time due to syncing the onchain wallet, registering boards,
	/// syncing rounds, arkoors, and the exit system, checking pending lightning payments and
	/// refreshing VTXOs if necessary.
	pub async fn maintenance_with_onchain<W: PreparePsbt + SignPsbt + ExitUnilaterally>(
		&self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		info!("Starting wallet maintenance with onchain wallet");
		self.sync().await;
		self.maintenance_refresh().await?;

		// NB: order matters here, after syncing lightning, we might have new exits to start
		self.sync_exits(onchain).await?;

		Ok(())
	}

	/// Checks VTXOs that are due to be refreshed, and schedules a refresh if any
	///
	/// This will include any VTXOs within the expiry threshold
	/// ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundStateId] if a refresh is scheduled.
	pub async fn maybe_schedule_maintenance_refresh(&self) -> anyhow::Result<Option<RoundStateId>> {
		let vtxos = self.get_vtxos_to_refresh().await?.into_iter()
			.map(|v| v.id())
			.collect::<Vec<_>>();
		if vtxos.len() == 0 {
			return Ok(None);
		}

		info!("Scheduling maintenance refresh");
		let mut participation = match self.build_refresh_participation(vtxos)? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		if let Err(e) = self.add_should_refresh_vtxos(&mut participation).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		let state = self.join_next_round(participation, Some(RoundMovement::Refresh)).await?;
		Ok(Some(state.id))
	}

	/// Performs a refresh of all VTXOs that are due to be refreshed, if any. This will include any
	/// VTXOs within the expiry threshold ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundStatus] if a refresh occurs.
	pub async fn maintenance_refresh(&self) -> anyhow::Result<Option<RoundStatus>> {
		let vtxos = self.get_vtxos_to_refresh().await?.into_iter()
			.map(|v| v.id())
			.collect::<Vec<_>>();
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
				if let Err(e) = self.sync_oors().await {
					warn!("Error in arkoor sync: {:#}", e);
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
		self.exit.write().await.sync(onchain).await?;
		Ok(())
	}

	pub fn pending_lightning_sends(&self) -> anyhow::Result<Vec<LightningSend>> {
		Ok(self.db.get_all_pending_lightning_send()?)
	}

	/// Syncs pending lightning payments, verifying whether the payment status has changed and
	/// creating a revocation VTXO if necessary.
	pub async fn sync_pending_lightning_send_vtxos(&self) -> anyhow::Result<()> {
		let pending_payments = self.pending_lightning_sends()?;

		if pending_payments.is_empty() {
			return Ok(());
		}

		info!("Syncing {} pending lightning sends", pending_payments.len());

		for payment in pending_payments {
			let payment_hash = payment.invoice.payment_hash();
			self.check_lightning_payment(payment_hash, false).await?;
		}

		Ok(())
	}

	/// Drop a specific [Vtxo] from the database. This is destructive and will result in a loss of
	/// funds.
	pub async fn dangerous_drop_vtxo(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		warn!("Drop vtxo {} from the database", vtxo_id);
		self.db.remove_vtxo(vtxo_id)?;
		Ok(())
	}

	/// Drop all VTXOs from the database. This is destructive and will result in a loss of funds.
	//TODO(stevenroose) improve the way we expose dangerous methods
	pub async fn dangerous_drop_all_vtxos(&self) -> anyhow::Result<()> {
		warn!("Dropping all vtxos from the db...");
		for vtxo in self.vtxos()? {
			self.db.remove_vtxo(vtxo.id())?;
		}

		self.exit.write().await.dangerous_clear_exit()?;
		Ok(())
	}

	/// Board a [Vtxo] with the given amount.
	///
	/// NB we will spend a little more onchain to cover fees.
	pub async fn board_amount(
		&self,
		onchain: &mut dyn onchain::Board,
		amount: Amount,
	) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(onchain, Some(amount), user_keypair).await
	}

	/// Board a [Vtxo] with all the funds in your onchain wallet.
	pub async fn board_all(
		&self,
		onchain: &mut dyn onchain::Board,
	) -> anyhow::Result<PendingBoard> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(onchain, None, user_keypair).await
	}

	async fn board(
		&self,
		wallet: &mut dyn onchain::Board,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<PendingBoard> {
		let mut srv = self.require_server()?;
		let ark_info = srv.ark_info().await?;

		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.chain.tip().await?;

		let expiry_height = current_height + ark_info.vtxo_expiry_delta as BlockHeight;
		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			ark_info.server_pubkey,
			ark_info.vtxo_exit_delta,
		);

		let addr = bitcoin::Address::from_script(
			&builder.funding_script_pubkey(),
			properties.network,
		)?;

		// We create the board tx template, but don't sign it yet.
		let fee_rate = self.chain.fee_rates().await.regular;
		let (board_psbt, amount) = if let Some(amount) = amount {
			let psbt = wallet.prepare_tx(&[(addr, amount)], fee_rate)?;
			(psbt, amount)
		} else {
			let psbt = wallet.prepare_drain_tx(addr, fee_rate)?;
			assert_eq!(psbt.unsigned_tx.output.len(), 1);
			let amount = psbt.unsigned_tx.output[0].value;
			(psbt, amount)
		};

		ensure!(amount >= ark_info.min_board_amount,
			"board amount of {amount} is less than minimum board amount required by server ({})",
			ark_info.min_board_amount,
		);

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
		let builder = builder
			.set_funding_details(amount, utxo)
			.generate_user_nonces();

		let cosign_resp = srv.client.request_board_cosign(protos::BoardCosignRequest {
			amount: amount.to_sat(),
			utxo: bitcoin::consensus::serialize(&utxo), //TODO(stevenroose) change to own
			expiry_height,
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		}).await.context("error requesting board cosign")?
			.into_inner().try_into().context("invalid cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid board cosignature received from server",
		);

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = builder.build_vtxo(&cosign_resp, &user_keypair)?;

		let onchain_fee = board_psbt.fee()?;
		let movement_id = self.movements.new_movement_with_update(
			self.subsystem_ids[&BarkSubsystem::Board],
			BoardMovement::Board.to_string(),
			MovementUpdate::new()
				.produced_vtxo(&vtxo)
				.intended_and_effective_balance(vtxo.amount().to_signed()?)
				.metadata(BoardMovement::metadata(utxo, onchain_fee)?),
		).await?;
		self.store_locked_vtxos([&vtxo], Some(movement_id))?;

		let tx = wallet.finish_tx(board_psbt)?;
		self.db.store_pending_board(&vtxo, &tx, movement_id)?;

		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.chain.broadcast_tx(&tx).await?;

		info!("Board broadcasted");
		Ok(self.db.get_pending_board_by_vtxo_id(vtxo.id())?.expect("board should be stored"))
	}

	/// Registers a board to the Ark server
	async fn register_board(&self, vtxo: impl VtxoRef) -> anyhow::Result<()> {
		trace!("Attempting to register board {} to server", vtxo.vtxo_id());
		let mut srv = self.require_server()?;

		// Get the vtxo and funding transaction from the database
		let vtxo = match vtxo.vtxo() {
			Some(v) => v,
			None => {
				&self.db.get_wallet_vtxo(vtxo.vtxo_id())?
					.with_context(|| format!("VTXO doesn't exist: {}", vtxo.vtxo_id()))?
			},
		};

		// Register the vtxo with the server
		srv.client.register_board_vtxo(protos::BoardVtxoRequest {
			board_vtxo: vtxo.serialize(),
		}).await.context("error registering board with the Ark server")?;

		// Remember that we have stored the vtxo
		// No need to complain if the vtxo is already registered
		self.db.update_vtxo_state_checked(vtxo.id(), VtxoState::Spendable, &UNSPENT_STATES)?;

		let board = self.db.get_pending_board_by_vtxo_id(vtxo.id())?
			.context("pending board not found")?;

		self.movements.finish_movement(board.movement_id, MovementStatus::Successful).await?;
		self.db.remove_pending_board(&vtxo.id())?;

		Ok(())
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet
	///
	/// An arkoor vtxo is considered to have some counterparty risk
	/// if it is (directly or not) based on round VTXOs that aren't owned by the wallet
	fn has_counterparty_risk(&self, vtxo: &Vtxo) -> anyhow::Result<bool> {
		for past_pk in vtxo.past_arkoor_pubkeys() {
			if !self.db.get_public_key_idx(&past_pk)?.is_some() {
				return Ok(true);
			}
		}
		Ok(!self.db.get_public_key_idx(&vtxo.user_pubkey())?.is_some())
	}

	pub async fn sync_oors(&self) -> anyhow::Result<()> {
		let last_pk_index = self.db.get_last_vtxo_key_index()?.unwrap_or_default();
		let pubkeys = (0..=last_pk_index).map(|idx| {
			self.vtxo_seed.derive_keypair(idx).public_key()
		}).collect::<Vec<_>>();

		self.sync_arkoor_for_pubkeys(&pubkeys).await?;

		Ok(())
	}

	/// Sync with the Ark server and look for out-of-round received VTXOs by public key.
	async fn sync_arkoor_for_pubkeys(
		&self,
		public_keys: &[PublicKey],
	) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		for pubkeys in public_keys.chunks(rpc::MAX_NB_MAILBOX_PUBKEYS) {
			// Then sync OOR vtxos.
			debug!("Emptying OOR mailbox at Ark server...");
			let req = protos::ArkoorVtxosRequest {
				pubkeys: pubkeys.iter().map(|pk| pk.serialize().to_vec()).collect(),
			};

			#[allow(deprecated)]
			let packages = srv.client.empty_arkoor_mailbox(req).await
				.context("error fetching oors")?.into_inner().packages;
			debug!("Ark server has {} arkoor packages for us", packages.len());

			for package in packages {
				let mut vtxos = Vec::with_capacity(package.vtxos.len());
				for vtxo in package.vtxos {
					let vtxo = match Vtxo::deserialize(&vtxo) {
						Ok(vtxo) => vtxo,
						Err(e) => {
							warn!("Invalid vtxo from Ark server: {}", e);
							continue;
						}
					};

					if let Err(e) = self.validate_vtxo(&vtxo).await {
						error!("Received invalid arkoor VTXO from server: {}", e);
						continue;
					}

					match self.db.has_spent_vtxo(vtxo.id()) {
						Ok(spent) if spent => {
							debug!("Not adding OOR vtxo {} because it is considered spent", vtxo.id());
							continue;
						},
						_ => {}
					}

					if let Ok(Some(_)) = self.db.get_wallet_vtxo(vtxo.id()) {
						debug!("Not adding OOR vtxo {} because it already exists", vtxo.id());
						continue;
					}

					vtxos.push(vtxo);
				}

				self.store_spendable_vtxos(&vtxos)?;
				self.movements.new_finished_movement(
					self.subsystem_ids[&BarkSubsystem::Arkoor],
					ArkoorMovement::Receive.to_string(),
					MovementStatus::Successful,
					MovementUpdate::new()
						.produced_vtxos(&vtxos)
						.intended_and_effective_balance(
							vtxos
							.iter()
							.map(|vtxo| vtxo.amount()).sum::<Amount>()
							.to_signed()?,
						),
				).await?;
			}
		}

		Ok(())
	}

	/// If there are any VTXOs that match the "should-refresh" condition with
	/// a total value over the  p2tr dust limit, they are added to the round
	/// participation and an additional output is also created.
	async fn add_should_refresh_vtxos(
		&self,
		participation: &mut RoundParticipation,
	) -> anyhow::Result<()> {
		let excluded_ids = participation.inputs.iter().map(|v| v.vtxo_id())
			.collect::<HashSet<_>>();

		let should_refresh_vtxos = self.get_vtxos_to_refresh().await?.into_iter()
			.filter(|v| !excluded_ids.contains(&v.id()))
			.map(|v| v.vtxo).collect::<Vec<_>>();


		let total_amount = should_refresh_vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		if total_amount > P2TR_DUST {
			let (user_keypair, _) = self.derive_store_next_keypair()?;
			let req = VtxoRequest {
				policy: VtxoPolicy::new_pubkey(user_keypair.public_key()),
				amount: total_amount,
			};

			participation.inputs.extend(should_refresh_vtxos);
			participation.outputs.push(req);
		}

		Ok(())
	}

	pub async fn offboard<V: VtxoRef>(
		&self,
		_vtxos: impl IntoIterator<Item = V>,
		_destination: ScriptBuf,
	) -> anyhow::Result<RoundStatus> {
		unimplemented!("offboards are currently unsupported");
	}

	/// Offboard all VTXOs to a given [bitcoin::Address].
	pub async fn offboard_all(&self, address: bitcoin::Address) -> anyhow::Result<RoundStatus> {
		let input_vtxos = self.spendable_vtxos()?;
		Ok(self.offboard(input_vtxos, address.script_pubkey()).await?)
	}

	/// Offboard the given VTXOs to a given [bitcoin::Address].
	pub async fn offboard_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
		address: bitcoin::Address,
	) -> anyhow::Result<RoundStatus> {
		let input_vtxos =  vtxos
			.into_iter()
			.map(|v| {
				let id = v.vtxo_id();
				match self.db.get_wallet_vtxo(id)? {
					Some(vtxo) => Ok(vtxo.vtxo),
					_ => bail!("cannot find requested vtxo: {}", id),
				}
			})
			.collect::<anyhow::Result<Vec<_>>>()?;

		Ok(self.offboard(input_vtxos, address.script_pubkey()).await?)
	}

	pub fn build_refresh_participation<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<RoundParticipation>> {
		let vtxos = {
			let mut ret = HashMap::new();
			for v in vtxos {
				let id = v.vtxo_id();
				let vtxo = self.get_vtxo_by_id(id)
					.with_context(|| format!("vtxo with id {} not found", id))?;
				if !ret.insert(id, vtxo).is_none() {
					bail!("duplicate VTXO id: {}", id);
				}
			}
			ret
		};

		if vtxos.is_empty() {
			info!("Skipping refresh since no VTXOs are provided.");
			return Ok(None);
		}

		let total_amount = vtxos.values().map(|v| v.vtxo.amount()).sum();

		info!("Refreshing {} VTXOs (total amount = {}).", vtxos.len(), total_amount);

		let (user_keypair, _) = self.derive_store_next_keypair()?;
		let req = VtxoRequest {
			policy: VtxoPolicy::Pubkey(PubkeyVtxoPolicy { user_pubkey: user_keypair.public_key() }),
			amount: total_amount,
		};

		Ok(Some(RoundParticipation {
			inputs: vtxos.into_values().map(|v| v.vtxo).collect(),
			outputs: vec![req],
		}))
	}

	/// This will refresh all provided VTXOs. Note that attempting to refresh a board VTXO which
	/// has not yet confirmed will result in an error.
	///
	/// Returns the [RoundStatus] of the round if a successful refresh occurred.
	/// It will return [None] if no [Vtxo] needed to be refreshed.
	pub async fn refresh_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<RoundStatus>> {
		let mut participation = match self.build_refresh_participation(vtxos)? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		if let Err(e) = self.add_should_refresh_vtxos(&mut participation).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(Some(self.participate_round(participation, Some(RoundMovement::Refresh)).await?))
	}

	/// This will find all VTXOs that meets must-refresh criteria.
	/// Then, if there are some VTXOs to refresh, it will
	/// also add those that meet should-refresh criteria.
	pub async fn get_vtxos_to_refresh(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let tip = self.chain.tip().await?;
		let fee_rate = self.chain.fee_rates().await.fast;

		// Check if there is any VTXO that we must refresh
		let must_refresh_vtxos = self.spendable_vtxos_with(
			&RefreshStrategy::must_refresh(self, tip, fee_rate),
		)?;
		if must_refresh_vtxos.is_empty() {
			return Ok(vec![]);
		} else {
			// If we need to do a refresh, we take all the should_refresh vtxo's as well
			// This helps us to aggregate some VTXOs
			let should_refresh_vtxos = self.spendable_vtxos_with(
				&RefreshStrategy::should_refresh(self, tip, fee_rate),
			)?;
			Ok(should_refresh_vtxos)
		}
	}

	/// Returns the block height at which the first VTXO will expire
	pub fn get_first_expiring_vtxo_blockheight(
		&self,
	) -> anyhow::Result<Option<BlockHeight>> {
		Ok(self.spendable_vtxos()?.iter().map(|v| v.expiry_height()).min())
	}

	/// Returns the next block height at which we have a VTXO that we
	/// want to refresh
	pub fn get_next_required_refresh_blockheight(
		&self,
	) -> anyhow::Result<Option<BlockHeight>> {
		let first_expiry = self.get_first_expiring_vtxo_blockheight()?;
		Ok(first_expiry.map(|h| h.saturating_sub(self.config.vtxo_refresh_expiry_threshold)))
	}

	/// Select several vtxos to cover the provided amount
	///
	/// Returns an error if amount cannot be reached
	///
	/// If `max_depth` is set, it will filter vtxos that have a depth greater than it.
	fn select_vtxos_to_cover(
		&self,
		amount: Amount,
		expiry_threshold: Option<BlockHeight>,
	) -> anyhow::Result<Vec<Vtxo>> {
		let inputs = self.spendable_vtxos()?;

		// Iterate over all rows until the required amount is reached
		let mut result = Vec::new();
		let mut total_amount = bitcoin::Amount::ZERO;
		for input in inputs {
			// Check if vtxo is soon-to-expire for arkoor payments
			if let Some(threshold) = expiry_threshold {
				if input.expiry_height() < threshold {
					warn!("VTXO {} is expiring soon (expires at {}, threshold {}), \
						skipping for arkoor payment",
						input.id(), input.expiry_height(), threshold,
					);
					continue;
				}
			}

			total_amount += input.amount();
			result.push(input.vtxo);

			if total_amount >= amount {
				return Ok(result)
			}
		}

		bail!("Insufficient money available. Needed {} but {} is available",
			amount, total_amount,
		);
	}

	/// Fetches all pending lightning receives ordered from newest to oldest.
	pub fn pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(self.db.get_all_pending_lightning_receives()?)
	}

	pub fn claimable_lightning_receive_balance(&self) -> anyhow::Result<Amount> {
		let receives = self.pending_lightning_receives()?;

		let mut total = Amount::ZERO;
		for receive in receives {
			if let Some(htlc_vtxos) = receive.htlc_vtxos {
				total += htlc_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
			}
		}

		Ok(total)
	}

	/// Starts a daemon for the wallet, for more information see [Daemon].
	///
	/// Note:
	/// - This function doesn't check if a daemon is already running,
	/// so it's possible to start multiple daemons by mistake.
	pub async fn run_daemon(
		self: &Arc<Self>,
		shutdown: CancellationToken,
		onchain: Arc<RwLock<dyn DaemonizableOnchainWallet>>,
	) -> anyhow::Result<()> {
		let daemon = Daemon::new(shutdown, self.clone(), onchain)?;

		tokio::spawn(async move {
			daemon.run().await;
		});

		Ok(())
	}
}
