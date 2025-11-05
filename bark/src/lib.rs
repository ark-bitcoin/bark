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
//! 	let address: ark::Address = wallet.new_address()?;
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
//! use bark::vtxo_selection::RefreshStrategy;
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
//!	wallet.refresh_vtxos(vtxos).await?;
//! 	Ok(())
//! }
//! ```



pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate serde;

pub mod exit;
pub mod movement;
pub mod onchain;
pub mod persist;
pub mod round;
pub mod lightning_utils;
pub mod vtxo_state;
pub mod vtxo_selection;

pub use self::config::Config;
pub use self::persist::sqlite::SqliteClient;
pub use self::vtxo_state::WalletVtxo;

mod config;
mod lnurl;
mod psbtext;


use std::collections::{HashMap, HashSet};

use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf};
use bitcoin::bip32::{self, Fingerprint};
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use futures::StreamExt;
use lightning_invoice::Bolt11Invoice;
use lightning::util::ser::Writeable;
use lnurllib::lightning_address::LightningAddress;
use log::{trace, debug, info, warn, error};

use ark::{ArkInfo, OffboardRequest, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::address::VtxoDelivery;
use ark::arkoor::ArkoorPackageBuilder;
use ark::board::{BoardBuilder, BOARD_FUNDING_TX_VTXO_VOUT};
use ark::lightning::{Bolt12Invoice, Bolt12InvoiceExt, Invoice, Offer, Preimage, PaymentHash};
use ark::musig;
use ark::rounds::RoundId;
use ark::vtxo::{VtxoRef, PubkeyVtxoPolicy, VtxoPolicyKind};
use bitcoin_ext::{AmountExt, BlockDelta, BlockHeight, P2TR_DUST, TxStatus};
use server_rpc::{self as rpc, protos, ServerConnection};

use crate::exit::Exit;
use crate::movement::{Movement, MovementArgs, MovementKind};
use crate::onchain::{ChainSource, PreparePsbt, ExitUnilaterally, Utxo, GetWalletTx, SignPsbt};
use crate::persist::BarkPersister;
use crate::persist::models::{PendingLightningSend, LightningReceive};
use crate::round::{RoundParticipation, RoundStatus};
use crate::vtxo_selection::{FilterVtxos, VtxoFilter, RefreshStrategy};
use crate::vtxo_state::{VtxoState, VtxoStateKind, UNSPENT_STATES};

const ARK_PURPOSE_INDEX: u32 = 350;

/// Leniency delta to allow claim when blocks were mined between htlc
/// receive and claim preparation
const LIGHTNING_PREPARE_CLAIM_DELTA: BlockDelta = 2;

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
	pub pending_lightning_receive: LightningReceiveBalance,
	/// Coins locked in a round.
	pub pending_in_round: Amount,
	/// Coins that are in the process of unilaterally exiting the Ark.
	/// None if exit subsystem was unavailable
	pub pending_exit: Option<Amount>,
	/// Coins that are pending sufficient confirmations from board transactions.
	pub pending_board: Amount,
}

struct ArkoorCreateResult {
	input: Vec<Vtxo>,
	created: Vec<Vtxo>,
	change: Option<Vtxo>,
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

/// Describes a completed transition of funds from onchain to offchain.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Board {
	/// The [bitcoin::Txid] of the funding-transaction.
	/// This is the transaction that has to be confirmed
	/// onchain for the board to succeed.
	pub funding_txid: bitcoin::Txid,
	/// The info for each [ark::Vtxo] that was created
	/// in this board.
	///
	/// Currently, this is always a vector of length 1
	pub vtxos: Vec<Vtxo>,
}

/// Describes a completed transition of funds from offchain to onchain collaboratively with the
/// Ark server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Offboard {
	/// The [RoundId] of the round in which the offboard occurred
	pub round: RoundId,
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
///     - [Wallet::send_lightning_payment],
///     - [Wallet::send_lnaddr],
///     - [Wallet::pay_offer]
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
///     - [Wallet::check_and_claim_all_open_ln_receives]: Wait for payment receipt of all open invoices, then claim them,
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
/// let addr = wallet.new_address()?;
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
	pub exit: tokio::sync::RwLock<Exit>,

	/// Active runtime configuration for networking, fees, policies and thresholds.
	config: Config,

	/// Persistence backend for wallet state (keys metadata, VTXOs, movements, round state, etc.).
	db: Arc<dyn BarkPersister>,

	/// Deterministic seed material used to derive VTXO ownership keypairs and addresses.
	vtxo_seed: VtxoSeed,

	/// Optional live connection to an Ark server for round participation and synchronization.
	server: Option<ServerConnection>,

}

impl Wallet {
	/// Creates a [onchain::ChainSource] instance to communicate with an onchain backend from the
	/// given [Config].
	pub fn chain_source<P: BarkPersister>(
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
	pub fn new_address(&self) -> anyhow::Result<ark::Address> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.derive_store_next_keypair()?.0.public_key();

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Peak for an [ark::Address] at the given key index.
	///
	/// May return an error if the address at the given index has not been derived yet.
	pub fn peak_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let pubkey = self.peak_keypair(index)?.public_key();

		Ok(ark::Address::builder()
			.testnet(network != Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address().unwrap())
	}

	/// Generate a new [ark::Address] and returns the index of the key used to create it.
	///
	/// This derives and stores the keypair directly after currently last revealed one.
	pub fn new_address_with_index(&self) -> anyhow::Result<(ark::Address, u32)> {
		let ark = &self.require_server()?;
		let network = self.properties()?.network;
		let (keypair, index) = self.derive_store_next_keypair()?;
		let pubkey = keypair.public_key();
		let addr = ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(ark.info.server_pubkey)
			.pubkey_policy(pubkey)
			.into_address()?;
		Ok((addr, index))
	}

	/// Create a new wallet without an optional onchain backend. This will restrict features such as
	/// boarding and unilateral exit.
	///
	/// The `force` flag will allow you to create the wallet even if a connection to the Ark server
	/// cannot be established, it will not overwrite a wallet which has already been created.
	pub async fn create<P: BarkPersister>(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<P>,
		force: bool,
	) -> anyhow::Result<Wallet> {
		trace!("Config: {:?}", config);
		if let Some(existing) = db.read_properties()? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		if !force {
			if let Err(_) = ServerConnection::connect(&config.server_address, network).await {
				bail!("Not connected to a server. If you are sure use the --force flag.");
			}
		}

		let wallet_fingerprint = VtxoSeed::new(network, &mnemonic.to_seed("")).fingerprint();
		let properties = WalletProperties {
			network: network,
			fingerprint: wallet_fingerprint,
		};

		// write the config to db
		db.init_wallet(&properties).context("cannot init wallet in the database")?;

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
	pub async fn create_with_onchain<P: BarkPersister, W: ExitUnilaterally>(
		mnemonic: &Mnemonic,
		network: Network,
		config: Config,
		db: Arc<P>,
		onchain: &W,
		force: bool,
	) -> anyhow::Result<Wallet> {
		let mut wallet = Wallet::create(mnemonic, network, config, db, force).await?;
		wallet.exit.get_mut().load(onchain).await?;
		Ok(wallet)
	}

	/// Loads the bark wallet from the given database ensuring the fingerprint remains consistent.
	pub async fn open<P: BarkPersister>(
		mnemonic: &Mnemonic,
		db: Arc<P>,
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

		let exit = tokio::sync::RwLock::new(Exit::new(db.clone(), chain.clone()).await?);

		Ok(Wallet { config, db, vtxo_seed, exit, server, chain })
	}

	/// Similar to [Wallet::open] however this also unilateral exits using the provided onchain
	/// wallet.
	pub async fn open_with_onchain<P: BarkPersister, W: ExitUnilaterally>(
		mnemonic: &Mnemonic,
		db: Arc<P>,
		onchain: &W,
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
		self.server.clone().context("You should be connected to Ark server to perform this action")
	}

	/// Return [ArkInfo] fetched on last handshake with the Ark server
	pub fn ark_info(&self) -> Option<&ArkInfo> {
		self.server.as_ref().map(|a| &a.info)
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

		let pending_lightning_receive = self.pending_lightning_receive_balance()?;

		let pending_board = self.pending_board_vtxos()?.iter().map(|v| v.amount()).sum::<Amount>();

		let pending_in_round = self.pending_round_input_vtxos()?.iter().map(|v| v.amount()).sum();

		let pending_exit = self.exit.try_read().ok().map(|e| e.pending_total());

		Ok(Balance {
			spendable,
			pending_in_round,
			pending_lightning_send,
			pending_lightning_receive,
			pending_exit,
			pending_board,
		})
	}

	/// Retrieves the full state of a [Vtxo] for a given [VtxoId] if it exists in the database.
	pub fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<WalletVtxo> {
		let vtxo = self.db.get_wallet_vtxo(vtxo_id)
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	/// Fetches all wallet fund movements ordered from newest to oldest.
	pub fn movements(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(self.db.get_movements()?)
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

	/// Queries the database for any VTXO that is an unregistered board. There is a lag time between
	/// when a board is created and when it becomes spendable.
	///
	/// See [ArkInfo::required_board_confirmations] and [Wallet::sync_pending_boards].
	pub fn pending_board_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxos = self.db.get_all_pending_boards()?.iter()
			.map(|vtxo_id| self.get_vtxo_by_id(*vtxo_id))
			.collect::<anyhow::Result<Vec<_>>>()?;

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

	/// Queries the database for any VTXO that is an pending lightning send.
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
		let ark_info = self.require_server()?.info;
		let current_height = self.chain.tip().await?;
		let unregistered_boards = self.pending_board_vtxos()?;
		let mut registered_boards = 0;

		if unregistered_boards.is_empty() {
			return Ok(());
		}

		trace!("Attempting registration of sufficiently confirmed boards");

		for board in unregistered_boards {
			let anchor = board.vtxo.chain_anchor();
			let confs = match self.chain.tx_status(anchor.txid).await {
				Ok(TxStatus::Confirmed(block_ref)) => Some(current_height - (block_ref.height - 1)),
				Ok(TxStatus::Mempool) => Some(0),
				Ok(TxStatus::NotFound) => None,
				Err(_) => None,
			};

			if let Some(confs) = confs {
				if confs >= ark_info.required_board_confirmations as BlockHeight {
					if let Err(e) = self.register_board(board.vtxo.id()).await {
						warn!("Failed to register board {}: {}", board.vtxo.id(), e);
					} else {
						info!("Registered board {}", board.vtxo.id());
						registered_boards += 1;
					}
				}
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
	/// payments and refreshing VTXOs if necessary.
	pub async fn maintenance(&self) -> anyhow::Result<()> {
		info!("Starting wallet maintenance");
		self.sync().await;
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

	/// Performs a refresh of all VTXOs that are due to be refreshed, if any. This will include any
	/// VTXOs within the expiry threshold ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Returns a [RoundId] if a refresh occurs.
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
	///   - even when onchain wallet is provided, the onchain wallet will not be sync, but
	///     - [Wallet::sync_pending_lightning_send_vtxos] will be called
	///   - [Wallet::sync_exits] will not be called
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
				if let Err(e) = self.claim_all_pending_htlc_recvs().await {
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
	pub async fn sync_exits<W: ExitUnilaterally>(
		&self,
		onchain: &mut W,
	) -> anyhow::Result<()> {
		self.exit.write().await.sync_exit(onchain).await?;
		Ok(())
	}

	/// Syncs pending lightning payments, verifying whether the payment status has changed and
	/// creating a revocation VTXO if necessary.
	pub async fn sync_pending_lightning_send_vtxos(&self) -> anyhow::Result<()> {
		let pending_payments = self.db.get_all_pending_lightning_send()?;

		if pending_payments.is_empty() {
			return Ok(());
		}

		info!("Syncing {} pending lightning sends", pending_payments.len());

		for payment in pending_payments {
			self.check_lightning_payment(&payment).await?;
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

		self.exit.write().await.clear_exit()?;
		Ok(())
	}

	/// Board a [Vtxo] with the given amount.
	///
	/// NB we will spend a little more onchain to cover fees.
	pub async fn board_amount<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&self,
		onchain: &mut W,
		amount: Amount,
	) -> anyhow::Result<Board> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(onchain, Some(amount), user_keypair).await
	}

	/// Board a [Vtxo] with all the funds in your onchain wallet.
	pub async fn board_all<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&self,
		onchain: &mut W,
	) -> anyhow::Result<Board> {
		let (user_keypair, _) = self.derive_store_next_keypair()?;
		self.board(onchain, None, user_keypair).await
	}

	async fn board<W: PreparePsbt + SignPsbt + GetWalletTx>(
		&self,
		wallet: &mut W,
		amount: Option<Amount>,
		user_keypair: Keypair,
	) -> anyhow::Result<Board> {
		let mut srv = self.require_server()?;
		let properties = self.db.read_properties()?.context("Missing config")?;
		let current_height = self.chain.tip().await?;

		let expiry_height = current_height + srv.info.vtxo_expiry_delta as BlockHeight;
		let builder = BoardBuilder::new(
			user_keypair.public_key(),
			expiry_height,
			srv.info.server_pubkey,
			srv.info.vtxo_exit_delta,
		);

		let addr = bitcoin::Address::from_script(
			&builder.funding_script_pubkey(),
			properties.network,
		).unwrap();

		// We create the board tx template, but don't sign it yet.
		let fee_rate = self.chain.fee_rates().await.regular;
		let (board_psbt, amount) = if let Some(amount) = amount {
			let psbt = wallet.prepare_tx([(addr, amount)], fee_rate)?;
			(psbt, amount)
		} else {
			let psbt = wallet.prepare_drain_tx(addr, fee_rate)?;
			assert_eq!(psbt.unsigned_tx.output.len(), 1);
			let amount = psbt.unsigned_tx.output[0].value;
			(psbt, amount)
		};

		ensure!(amount >= srv.info.min_board_amount,
			"board amount of {amount} is less than minimum board amount required by server ({})",
			srv.info.min_board_amount,
		);

		let utxo = OutPoint::new(board_psbt.unsigned_tx.compute_txid(), BOARD_FUNDING_TX_VTXO_VOUT);
		let builder = builder
			.set_funding_details(amount, utxo)
			.generate_user_nonces();

		let cosign_resp = srv.client.request_board_cosign(protos::BoardCosignRequest {
			amount: amount.to_sat(),
			utxo: bitcoin::consensus::serialize(&utxo), //TODO(stevenroose) change to own
			expiry_height: expiry_height,
			user_pubkey: user_keypair.public_key().serialize().to_vec(),
			pub_nonce: builder.user_pub_nonce().serialize().to_vec(),
		}).await.context("error requesting board cosign")?
			.into_inner().try_into().context("invalid cosign response from server")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid board cosignature received from server",
		);

		// Store vtxo first before we actually make the on-chain tx.
		let vtxo = builder.build_vtxo(&cosign_resp, &user_keypair)?;

		self.db.register_movement(MovementArgs {
			kind: MovementKind::Board,
			spends: &[],
			receives: &[(&vtxo, VtxoState::Locked)],
			recipients: &[],
			fees: None,
		}).context("db error storing vtxo")?;

		let tx = wallet.finish_tx(board_psbt)?;

		self.db.store_pending_board(&vtxo, &tx)?;

		trace!("Broadcasting board tx: {}", bitcoin::consensus::encode::serialize_hex(&tx));
		self.chain.broadcast_tx(&tx).await?;

		info!("Board broadcasted");
		Ok(Board {
			funding_txid: tx.compute_txid(),
			vtxos: vec![vtxo.into()],
		})
	}

	/// Registers a board to the Ark server
	async fn register_board(&self, vtxo: impl VtxoRef) -> anyhow::Result<Board> {
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
		self.db.update_vtxo_state_checked(vtxo.vtxo_id(), VtxoState::Spendable, &UNSPENT_STATES)?;

		self.db.remove_pending_board(&vtxo.vtxo_id())?;

		let funding_txid = vtxo.chain_anchor().txid;

		Ok(Board {
			funding_txid: funding_txid,
			vtxos: vec![vtxo.clone()],
		})
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

	async fn sync_oors(&self) -> anyhow::Result<()> {
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


					let txid = vtxo.chain_anchor().txid;
					let chain_anchor = self.chain.get_tx(&txid).await?.with_context(|| {
						format!("received arkoor vtxo with unknown chain anchor: {}", txid)
					})?;
					if let Err(e) = vtxo.validate(&chain_anchor) {
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

				self.db.register_movement(MovementArgs {
					kind: MovementKind::ArkoorReceive,
					spends: &[],
					receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
					recipients: &[],
					fees: None,
				}).context("failed to store OOR vtxo")?;
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

	pub fn build_offboard_participation<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
		destination: ScriptBuf,
	) -> anyhow::Result<RoundParticipation> {
		let srv = self.require_server()?;

		let vtxos = {
			let vtxos = vtxos.into_iter();
			let mut ret = Vec::with_capacity(vtxos.size_hint().0);
			for v in vtxos {
				let vtxo = match v.vtxo() {
					Some(v) => v.clone(),
					None => self.get_vtxo_by_id(v.vtxo_id()).context("vtxo not found")?.vtxo,
				};
				ret.push(vtxo);
			}
			ret
		};

		if vtxos.is_empty() {
			bail!("no VTXO to offboard");
		}

		let fee = OffboardRequest::calculate_fee(&destination, srv.info.offboard_feerate)
			.expect("bdk created invalid scriptPubkey");

		let vtxo_sum = vtxos.iter().map(|v| v.amount()).sum::<Amount>();

		if fee > vtxo_sum {
			bail!("offboarded amount is lower than fees. Need {fee}, got: {vtxo_sum}");
		}

		let offb = OffboardRequest {
			amount: vtxo_sum - fee,
			script_pubkey: destination.clone(),
		};

		Ok(RoundParticipation {
			inputs: vtxos.clone(),
			outputs: Vec::new(),
			offboards: vec![offb],
		})
	}

	async fn offboard<V: VtxoRef>(
		&mut self,
		vtxos: impl IntoIterator<Item = V>,
		destination: ScriptBuf,
	) -> anyhow::Result<RoundStatus> {
		let mut participation = self.build_offboard_participation(vtxos, destination.clone())?;

		if let Err(e) = self.add_should_refresh_vtxos(&mut participation).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(self.participate_round(participation).await?)
	}

	/// Offboard all VTXOs to a given [bitcoin::Address].
	pub async fn offboard_all(&mut self, address: bitcoin::Address) -> anyhow::Result<RoundStatus> {
		let input_vtxos = self.spendable_vtxos()?;
		Ok(self.offboard(input_vtxos, address.script_pubkey()).await?)
	}

	/// Offboard the given VTXOs to a given [bitcoin::Address].
	pub async fn offboard_vtxos<V: VtxoRef>(
		&mut self,
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
			offboards: Vec::new(),
		}))
	}

	/// This will refresh all provided VTXOs. Note that attempting to refresh a board VTXO which
	/// has not yet confirmed will result in an error.
	///
	/// Returns the [RoundId] of the round if a successful refresh occurred.
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

		Ok(Some(self.participate_round(participation).await?))
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
		max_depth: Option<u16>,
		expiry_threshold: Option<BlockHeight>,
	) -> anyhow::Result<Vec<Vtxo>> {
		let inputs = self.spendable_vtxos()?;

		// Iterate over all rows until the required amount is reached
		let mut result = Vec::new();
		let mut total_amount = bitcoin::Amount::ZERO;
		for input in inputs {
			if let Some(max_depth) = max_depth {
				if input.arkoor_depth() >= max_depth {
					warn!("VTXO {} reached max depth of {}, skipping it. \
						Please refresh your VTXO.", input.id(), max_depth,
					);
					continue;
				}
			}

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

	/// Create Arkoor VTXOs for a given destination and amount
	///
	/// Outputs cannot have more than one input, so we can create new
	/// arkoors for each input needed to match requested amount + one
	/// optional change output.
	async fn create_arkoor_vtxos(
		&self,
		destination_policy: VtxoPolicy,
		amount: Amount,
	) -> anyhow::Result<ArkoorCreateResult> {
		let mut srv = self.require_server()?;
		let change_pubkey = self.derive_store_next_keypair()?.0.public_key();

		let req = VtxoRequest {
			amount: amount,
			policy: destination_policy,
		};

		// Get current height for expiry checking
		let tip = self.chain.tip().await?;
		let inputs = self.select_vtxos_to_cover(
			req.amount,
			Some(srv.info.max_arkoor_depth),
			Some(tip + self.config.vtxo_refresh_expiry_threshold),
		)?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = self.get_vtxo_key(&input)?;
			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let builder = ArkoorPackageBuilder::new(&inputs, &pubs, req, Some(change_pubkey))?;

		let req = protos::ArkoorPackageCosignRequest {
			arkoors: builder.arkoors.iter().map(|a| a.into()).collect(),
		};
		let cosign_resp: Vec<_> = srv.client.request_arkoor_package_cosign(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (sent, change) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		if let Some(change) = change.as_ref() {
			info!("Added change VTXO of {}", change.amount());
		}

		Ok(ArkoorCreateResult {
			input: inputs,
			created: sent,
			change: change,
		})
	}

	/// Validate if we can send arkoor payments to the given [ark::Address], for example an error
	/// will be returned if the given [ark::Address] belongs to a different server (see
	/// [ark::address::ArkId]).
	pub fn validate_arkoor_address(&self, address: &ark::Address) -> anyhow::Result<()> {
		let asp = self.require_server()?;

		if !address.ark_id().is_for_server(asp.info.server_pubkey) {
			bail!("Ark address is for different server");
		}

		// Not all policies are supported for sending arkoor
		match address.policy().policy_type() {
			VtxoPolicyKind::Pubkey => {},
			VtxoPolicyKind::ServerHtlcRecv | VtxoPolicyKind::ServerHtlcSend => {
				bail!("VTXO policy in address cannot be used for arkoor payment: {}",
					address.policy().policy_type(),
				);
			}
		}

		if address.delivery().is_empty() {
			bail!("No VTXO delivery mechanism provided in address");
		}
		// We first see if we know any of the deliveries, if not, we will log
		// the unknown onces.
		// We do this in two parts because we shouldn't log unknown ones if there is one known.
		if !address.delivery().iter().any(|d| !d.is_unknown()) {
			for d in address.delivery() {
				if let VtxoDelivery::Unknown { delivery_type, data } = d {
					info!("Unknown delivery in address: type={:#x}, data={}",
						delivery_type, data.as_hex(),
					);
				}
			}
		}

		Ok(())
	}

	/// Makes an out-of-round payment to the given [ark::Address]. This does not require waiting for
	/// a round, so it should be relatively instantaneous.
	///
	/// If the [Wallet] doesn't contain a VTXO larger than the given [Amount], multiple payments
	/// will be chained together, resulting in the recipient receiving multiple VTXOs.
	///
	/// Note that a change [Vtxo] may be created as a result of this call. With each payment these
	/// will become more uneconomical to unilaterally exit, so you should eventually refresh them
	/// with [Wallet::refresh_vtxos] or periodically call [Wallet::maintenance_refresh].
	pub async fn send_arkoor_payment(
		&self,
		destination: &ark::Address,
		amount: Amount,
	) -> anyhow::Result<Vec<Vtxo>> {
		let mut srv = self.require_server()?;

		self.validate_arkoor_address(&destination).context("cannot send to address")?;

		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let arkoor = self.create_arkoor_vtxos(destination.policy().clone(), amount).await?;

		let req = protos::ArkoorPackage {
			arkoors: arkoor.created.iter().map(|v| protos::ArkoorVtxo {
				pubkey: destination.policy().user_pubkey().serialize().to_vec(),
				vtxo: v.serialize().to_vec(),
			}).collect(),
		};

		if let Err(e) = srv.client.post_arkoor_package_mailbox(req).await {
			error!("Failed to post the arkoor vtxo to the recipients mailbox: '{}'", e);
			//NB we will continue to at least not lose our own change
		}

		self.db.register_movement(MovementArgs {
			kind: MovementKind::ArkoorSend,
			spends: &arkoor.input.iter().collect::<Vec<_>>(),
			receives: &arkoor.change.as_ref()
				.map(|v| vec![(v, VtxoState::Spendable)])
				.unwrap_or(vec![]),
			recipients: &[(&destination.to_string(), amount)],
			fees: None,
		}).context("failed to store arkoor vtxo")?;

		Ok(arkoor.created)
	}

	async fn process_lightning_revocation(&self, payment: &PendingLightningSend) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;
		let htlc_vtxos = payment.htlc_vtxos.clone().into_iter()
			.map(|v: WalletVtxo| v.vtxo).collect::<Vec<_>>();

		info!("Processing {} HTLC VTXOs for revocation", htlc_vtxos.len());

		let mut secs = Vec::with_capacity(htlc_vtxos.len());
		let mut pubs = Vec::with_capacity(htlc_vtxos.len());
		let mut keypairs = Vec::with_capacity(htlc_vtxos.len());
		for input in htlc_vtxos.iter() {
			let keypair = self.get_vtxo_key(&input)?;
			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let revocation = ArkoorPackageBuilder::new_htlc_revocation(&htlc_vtxos, &pubs)?;

		let req = protos::RevokeLightningPaymentRequest {
			htlc_vtxo_ids: revocation.arkoors.iter()
				.map(|i| i.input.id().to_bytes().to_vec())
				.collect(),
			user_nonces: revocation.arkoors.iter()
				.map(|i| i.user_nonce.serialize().to_vec())
				.collect(),
		};
		let cosign_resp: Vec<_> = srv.client.revoke_lightning_payment(req).await?
			.into_inner().try_into().context("invalid server cosign response")?;
		ensure!(revocation.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (vtxos, _) = revocation.build_vtxos(&cosign_resp, &keypairs, secs)?;
		for vtxo in &vtxos {
			info!("Got revocation VTXO: {}: {}", vtxo.id(), vtxo.amount());
		}

		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningSendRevocation,
			spends: &htlc_vtxos.iter().collect::<Vec<_>>(),
			receives: &vtxos.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		})?;

		self.db.remove_pending_lightning_send(payment.invoice.payment_hash())?;

		info!("Revoked {} HTLC VTXOs", vtxos.len());

		Ok(())
	}

	/// Pays a Lightning [Invoice] using Ark VTXOs. This is also an out-of-round payment
	/// so the same [Wallet::send_arkoor_payment] rules apply.
	pub async fn send_lightning_payment<T>(
		&self,
		invoice: T,
		user_amount: Option<Amount>,
	) -> anyhow::Result<Preimage>
	where
		T: TryInto<Invoice>,
		T::Error: std::error::Error + fmt::Display + Send + Sync + 'static,
	{
		let mut srv = self.require_server()?;
		let properties = self.db.read_properties()?.context("Missing config")?;

		let invoice = invoice.try_into().context("failed to parse invoice")?;
		if invoice.network() != properties.network {
			bail!("Invoice is for wrong network: {}", invoice.network());
		}

		if self.db.check_recipient_exists(&invoice.to_string())? {
			bail!("Invoice has already been paid");
		}

		invoice.check_signature()?;

		let inv_amount = invoice.amount_msat().map(|v| Amount::from_msat_ceil(v));
		if let (Some(_), Some(inv)) = (user_amount, inv_amount) {
			bail!("Invoice has amount of {} encoded. Please omit user amount argument", inv);
		}

		let amount = user_amount.or(inv_amount)
			.context("amount required on invoice without amount")?;
		if amount < P2TR_DUST {
			bail!("Sent amount must be at least {}", P2TR_DUST);
		}

		let (change_keypair, _) = self.derive_store_next_keypair()?;

		let inputs = self.select_vtxos_to_cover(amount, Some(srv.info.max_arkoor_depth), None)
			.context("Could not find enough suitable VTXOs to cover lightning payment")?;

		let mut secs = Vec::with_capacity(inputs.len());
		let mut pubs = Vec::with_capacity(inputs.len());
		let mut keypairs = Vec::with_capacity(inputs.len());
		for input in inputs.iter() {
			let keypair = self.get_vtxo_key(&input)?;
			let (s, p) = musig::nonce_pair(&keypair);
			secs.push(s);
			pubs.push(p);
			keypairs.push(keypair);
		}

		let req = protos::StartLightningPaymentRequest {
			invoice: invoice.to_string(),
			user_amount_sat: user_amount.map(|a| a.to_sat()),
			input_vtxo_ids: inputs.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			user_nonces: pubs.iter().map(|p| p.serialize().to_vec()).collect(),
			user_pubkey: change_keypair.public_key().serialize().to_vec(),
		};

		let resp =  srv.client.start_lightning_payment(req).await
			.context("htlc request failed")?.into_inner();

		let cosign_resp = resp.sigs.into_iter().map(|i| i.try_into())
			.collect::<Result<Vec<_>, _>>()?;
		let policy = VtxoPolicy::deserialize(&resp.policy)?;

		let pay_req = match policy {
			VtxoPolicy::ServerHtlcSend(policy) => {
				ensure!(policy.user_pubkey == change_keypair.public_key(), "user pubkey mismatch");
				ensure!(policy.payment_hash == invoice.payment_hash(), "payment hash mismatch");
				// TODO: ensure expiry is not too high? add new bark config to check against?
				VtxoRequest { amount: amount, policy: policy.into() }
			},
			_ => bail!("invalid policy returned from server"),
		};

		let builder = ArkoorPackageBuilder::new(
			&inputs, &pubs, pay_req, Some(change_keypair.public_key()),
		)?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (htlc_vtxos, change_vtxo) = builder.build_vtxos(&cosign_resp, &keypairs, secs)?;

		// Validate the new vtxos. They have the same chain anchor.
		for (vtxo, input) in htlc_vtxos.iter().zip(inputs.iter()) {
			if let Ok(tx) = self.chain.get_tx(&input.chain_anchor().txid).await {
				let tx = tx.with_context(|| {
					format!("input vtxo chain anchor not found for lightning send htlc vtxo: {}", input.chain_anchor().txid)
				})?;
				vtxo.validate(&tx).context("invalid lightning htlc vtxo")?;
			} else {
				warn!("We couldn't validate the new VTXOs because of chain source error.");
			}
		}

		// Validate the change vtxo. It has the same chain anchor as the last input.
		if let Some(ref change) = change_vtxo {
			let last_input = inputs.last().context("no inputs provided")?;
			let tx = self.chain.get_tx(&last_input.chain_anchor().txid).await?;
			let tx = tx.with_context(|| {
				format!("input vtxo chain anchor not found for lightning change vtxo: {}", last_input.chain_anchor().txid)
			})?;
			change.validate(&tx).context("invalid lightning change vtxo")?;
		}

		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningSend,
			spends: &inputs.iter().collect::<Vec<_>>(),
			receives: &htlc_vtxos.iter()
				.map(|v| (v, VtxoState::Locked))
				.chain(change_vtxo.as_ref().map(|c| (c, VtxoState::Spendable)))
				.collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		}).context("failed to store OOR vtxo")?;

		let payment = self.db.store_new_pending_lightning_send(
			&invoice, &amount, &htlc_vtxos.iter().map(|v| v.id()).collect::<Vec<_>>(),
		)?;

		let req = protos::SignedLightningPaymentDetails {
			invoice: invoice.to_string(),
			htlc_vtxo_ids: htlc_vtxos.iter().map(|v| v.id().to_bytes().to_vec()).collect(),
			wait: true,
		};

		let res = srv.client.finish_lightning_payment(req).await?.into_inner();
		debug!("Progress update: {}", res.progress_message);
		let payment_preimage = Preimage::try_from(res.payment_preimage()).ok();

		if let Some(preimage) = payment_preimage {
			info!("Payment succeeded! Preimage: {}", preimage.as_hex());
			self.db.register_movement(MovementArgs {
				kind: MovementKind::LightningSend,
				spends: &htlc_vtxos.iter().collect::<Vec<_>>(),
				receives: &[],
				recipients: &[(&invoice.to_string(), amount)],
				fees: None,
			}).context("failed to store OOR vtxo")?;

			self.db.remove_pending_lightning_send(payment.invoice.payment_hash())?;
			Ok(preimage)
		} else {
			self.process_lightning_revocation(&payment).await?;
			bail!("No preimage, payment failed: {}", res.progress_message);
		}
	}

	/// Checks the status of a lightning payment associated with a set of VTXOs, processes the
	/// payment result and optionally takes appropriate actions based on the payment outcome.
	///
	/// # Arguments
	///
	/// * `htlc_vtxos` - Slice of [WalletVtxo] objects that represent HTLC outputs involved in the
	///                  payment.
	///
	/// # Returns
	///
	/// Returns `Ok(Some(Preimage))` if the payment is successfully completed and a preimage is
	/// received.
	/// Returns `Ok(None)` for payments still pending, failed payments or if necessary revocation
	/// or exit processing occurs.
	/// Returns an `Err` if an error occurs during the process.
	///
	/// # Behavior
	///
	/// - Validates that all HTLC VTXOs share the same invoice, amount and policy.
	/// - Sends a request to the lightning payment server to check the payment status.
	/// - Depending on the payment status:
	///   - **Failed**: Revokes the associated VTXOs.
	///   - **Pending**: Checks if the HTLC has expired based on the tip height. If expired,
	///     revokes the VTXOs.
	///   - **Complete**: Extracts the payment preimage, logs the payment, registers movement
	///     in the database and returns
	pub async fn check_lightning_payment(&self, payment: &PendingLightningSend)
		-> anyhow::Result<Option<Preimage>>
	{
		let mut srv = self.require_server()?;
		let tip = self.chain.tip().await?;

		let payment_hash = payment.invoice.payment_hash();

		let policy = payment.htlc_vtxos.first().context("no vtxo provided")?.vtxo.policy();
		debug_assert!(payment.htlc_vtxos.iter().all(|v| v.vtxo.policy() == policy),
			"All lightning htlc should have the same policy",
		);
		let policy = policy.as_server_htlc_send().context("VTXO is not an HTLC send")?;
		if policy.payment_hash != payment_hash {
			bail!("Payment hash mismatch");
		}

		let req = protos::CheckLightningPaymentRequest {
			hash: policy.payment_hash.to_vec(),
			wait: false,
		};
		let res = srv.client.check_lightning_payment(req).await?.into_inner();

		let payment_status = protos::PaymentStatus::try_from(res.status)?;

		let should_revoke = match payment_status {
			protos::PaymentStatus::Failed => {
				info!("Payment failed ({}): revoking VTXO", res.progress_message);
				true
			},
			protos::PaymentStatus::Pending => {
				trace!("Payment is still pending, HTLC expiry: {}, tip: {}",
					policy.htlc_expiry, tip);
				if tip > policy.htlc_expiry {
					info!("Payment is still pending, but HTLC is expired: revoking VTXO");
					true
				} else {
					info!("Payment is still pending and HTLC is not expired ({}): \
						doing nothing for now", policy.htlc_expiry,
					);
					false
				}
			},
			protos::PaymentStatus::Complete => {
				let preimage: Preimage = res.payment_preimage
					.context("payment completed but no preimage")?
					.try_into().map_err(|_| anyhow!("preimage is not 32 bytes"))?;
				info!("Payment is complete, preimage, {}", preimage.as_hex());

				self.db.register_movement(MovementArgs {
					kind: MovementKind::LightningSend,
					spends: &payment.htlc_vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>(),
					receives: &[],
					recipients: &[(&payment.invoice.to_string(), payment.amount)],
					fees: None,
				}).context("failed to store OOR vtxo")?;

				self.db.remove_pending_lightning_send(payment_hash)?;

				return Ok(Some(preimage));
			},
		};

		if should_revoke {
			if let Err(e) = self.process_lightning_revocation(payment).await {
				warn!("Failed to revoke VTXO: {}", e);

				// if one of the htlc is about to expire, we exit all of them.
				// Maybe we want a different behavior here, but we have to decide whether
				// htlc vtxos revocation is a all or nothing process.
				let min_expiry = payment.htlc_vtxos.iter()
					.map(|v| v.vtxo.spec().expiry_height).min().unwrap();

				if tip > min_expiry.saturating_sub(self.config().vtxo_refresh_expiry_threshold) {
					warn!("Some VTXO is about to expire soon, marking to exit");
					let vtxos = payment.htlc_vtxos
						.iter()
						.map(|v| v.vtxo.clone())
						.collect::<Vec<_>>();
					self.exit.write().await.mark_vtxos_for_exit(&vtxos);

					self.db.remove_pending_lightning_send(payment_hash)?;
				}
			}
		}

		Ok(None)
	}

	/// Create, store and return a [Bolt11Invoice] for offchain boarding
	pub async fn bolt11_invoice(&self, amount: Amount) -> anyhow::Result<Bolt11Invoice> {
		let mut srv = self.require_server()?;
		let config = self.config();

		// User needs to enfore the following delta:
		// - vtxo exit delta + htlc expiry delta (to give him time to exit the vtxo before htlc expires)
		// - vtxo exit margin (to give him time to exit the vtxo before htlc expires)
		// - htlc recv claim delta (to give him time to claim the htlc before it expires)
		let requested_min_cltv_delta = srv.info.vtxo_exit_delta +
			srv.info.htlc_expiry_delta +
			config.vtxo_exit_margin +
			config.htlc_recv_claim_delta +
			LIGHTNING_PREPARE_CLAIM_DELTA;

		if requested_min_cltv_delta > srv.info.max_user_invoice_cltv_delta {
			bail!("HTLC CLTV delta ({}) is greater than Server's max HTLC recv CLTV delta: {}",
				requested_min_cltv_delta,
				srv.info.max_user_invoice_cltv_delta,
			);
		}

		let preimage = Preimage::random();
		let payment_hash = preimage.compute_payment_hash();
		info!("Start bolt11 board with preimage / payment hash: {} / {}",
			preimage.as_hex(), payment_hash.as_hex());

		let req = protos::StartLightningReceiveRequest {
			payment_hash: payment_hash.to_vec(),
			amount_sat: amount.to_sat(),
			min_cltv_delta: requested_min_cltv_delta as u32,
		};

		let resp = srv.client.start_lightning_receive(req).await?.into_inner();
		info!("Ark Server is ready to receive LN payment to invoice: {}.", resp.bolt11);

		let invoice = Bolt11Invoice::from_str(&resp.bolt11)
			.context("invalid bolt11 invoice returned by Ark server")?;

		self.db.store_lightning_receive(
			payment_hash,
			preimage,
			&invoice,
			requested_min_cltv_delta,
		)?;

		Ok(invoice)
	}

	/// Fetches the status of a lightning receive for the given [PaymentHash].
	pub fn lightning_receive_status(
		&self,
		payment: impl Into<PaymentHash>,
	) -> anyhow::Result<Option<LightningReceive>> {
		Ok(self.db.fetch_lightning_receive_by_payment_hash(payment.into())?)
	}

	/// Fetches all pending lightning receives ordered from newest to oldest.
	pub fn pending_lightning_receives(&self) -> anyhow::Result<Vec<LightningReceive>> {
		Ok(self.db.get_all_pending_lightning_receives()?)
	}

	pub fn pending_lightning_receive_balance(&self) -> anyhow::Result<LightningReceiveBalance> {
		let pending_lightning_receives = self.pending_lightning_receives()?;

		let mut total_pending_lightning_receive = Amount::ZERO;
		let mut claimable_pending_lightning_receive = Amount::ZERO;
		for receive in pending_lightning_receives {
			total_pending_lightning_receive += receive.invoice.amount_milli_satoshis()
				.map(|a| Amount::from_msat_floor(a))
				.expect("ln receive invoice should have amount");
			if let Some(htlc_vtxos) = receive.htlc_vtxos {
				claimable_pending_lightning_receive += htlc_vtxos.iter().map(|v| v.amount()).sum::<Amount>();
			}
		}

		Ok(LightningReceiveBalance {
			total: total_pending_lightning_receive,
			claimable: claimable_pending_lightning_receive,
		})
	}

	/// Claim incoming lightning payment with the given [PaymentHash].
	///
	/// This function reveals the preimage of the lightning payment in
	/// exchange of getting pubkey VTXOs from HTLC ones
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to wait for.
	/// * `vtxos` - The list of HTLC VTXOs that were previously granted
	/// by the Server, with the hash lock clause matching payment hash.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<()>`, which is:
	/// * `Ok(())` if the process completes successfully.
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The list of HTLC VTXOs must have the hash lock clause matching the given
	///   [PaymentHash].
	async fn claim_ln_receive(
		&self,
		lightning_receive: &LightningReceive,
	) -> anyhow::Result<()> {
		let mut srv = self.require_server()?;

		// order inputs by vtxoid before we generate nonces
		let inputs = {
			let htlc_vtxos = lightning_receive.htlc_vtxos.as_ref()
				.context("no HTLC VTXOs set on record yet")?;
			let mut ret = htlc_vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>();
			ret.sort_by_key(|v| v.id());
			ret
		};

		let (keypairs, sec_nonces, pub_nonces) = inputs.iter().map(|v| {
			let keypair = self.get_vtxo_key(v)?;
			let (sec_nonce, pub_nonce) = musig::nonce_pair(&keypair);
			Ok((keypair, sec_nonce, pub_nonce))
		}).collect::<anyhow::Result<(Vec<_>, Vec<_>, Vec<_>)>>()?;

		// Claiming arkoor against preimage
		let (claim_keypair, _) = self.derive_store_next_keypair()?;
		let receive_policy = VtxoPolicy::new_pubkey(claim_keypair.public_key());

		let pay_req = VtxoRequest {
			policy: receive_policy.clone(),
			amount: inputs.iter().map(|v| v.amount()).sum(),
		};
		trace!("ln arkoor builder params: inputs: {:?}; user_nonces: {:?}; req: {:?}",
			inputs.iter().map(|v| v.id()).collect::<Vec<_>>(), pub_nonces, pay_req,
		);
		let builder = ArkoorPackageBuilder::new(
			inputs.iter().copied(), &pub_nonces, pay_req, None,
		)?;

		info!("Claiming arkoor against payment preimage");
		self.db.set_preimage_revealed(lightning_receive.payment_hash)?;
		let resp = srv.client.claim_lightning_receive(protos::ClaimLightningReceiveRequest {
			payment_hash: lightning_receive.payment_hash.to_byte_array().to_vec(),
			payment_preimage: lightning_receive.payment_preimage.to_vec(),
			vtxo_policy: receive_policy.serialize(),
			user_pub_nonces: pub_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		}).await?.into_inner();
		let cosign_resp: Vec<_> = resp.try_into().context("invalid cosign response")?;

		ensure!(builder.verify_cosign_response(&cosign_resp),
			"invalid arkoor cosignature received from server",
		);

		let (outputs, change) = builder.build_vtxos(&cosign_resp, &keypairs, sec_nonces)?;
		if change.is_some() {
			bail!("shouldn't have change VTXO, this is a bug");
		}

		for (vtxo, input) in outputs.iter().zip(inputs.iter()) {
			if let Ok(tx) = self.chain.get_tx(&input.chain_anchor().txid).await {
				let tx = tx.with_context(|| {
					format!("input vtxo chain anchor not found for lightning receive vtxo: {}", input.chain_anchor().txid)
				})?;
				vtxo.validate(&tx).context("invalid lightning receive htlc vtxo")?;
			} else {
				warn!("We couldn't validate the new VTXOs because of chain source error.");
			}
		}

		info!("Got arkoors from lightning: {}",
			outputs.iter().map(|v| v.id().to_string()).collect::<Vec<_>>().join(", "));
		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningReceive,
			spends: &inputs,
			receives: &outputs.iter().map(|v| (v, VtxoState::Spendable)).collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		})?;

		self.db.remove_pending_lightning_receive(lightning_receive.payment_hash)?;

		Ok(())
	}

	/// Check for incoming lightning payment with the given [PaymentHash].
	///
	/// This function checks for an incoming lightning payment with the
	/// given [PaymentHash] and returns the HTLC VTXOs that are associated
	/// with it.
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to check for.
	/// * `wait` - Whether to wait for the payment to be received.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<Vec<WalletVtxo>>`, which is:
	/// * `Ok(wallet_vtxos)` if the process completes successfully, where `wallet_vtxos` is
	///   the list of HTLC VTXOs that are associated with the payment.
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The invoice must contain an explicit amount specified in milli-satoshis.
	/// * The HTLC expiry height is calculated by adding the servers' HTLC expiry delta to the
	///   current chain tip.
	/// * The payment hash must be from an invoice previously generated using
	///   [Wallet::bolt11_invoice].
	pub async fn check_ln_receive(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<LightningReceive> {
		let mut srv = self.require_server()?;
		let current_height = self.chain.tip().await?;

		let mut lightning_receive = self.db.fetch_lightning_receive_by_payment_hash(payment_hash)?
			.context("no lightning receive found")?;

		info!("Waiting for payment...");
		let sub = srv.client.check_lightning_receive(protos::CheckLightningReceiveRequest {
			hash: payment_hash.to_byte_array().to_vec(), wait,
		}).await?.into_inner();

		let status = protos::LightningReceiveStatus::try_from(sub.status)
			.with_context(|| format!("unknown payment status: {}", sub.status))?;
		match status {
			// this is the good case
			protos::LightningReceiveStatus::Accepted
				| protos::LightningReceiveStatus::HtlcsReady => {},
			protos::LightningReceiveStatus::Created => bail!("sender didn't initiate payment yet"),
			protos::LightningReceiveStatus::Settled => bail!("payment already settled"),
			protos::LightningReceiveStatus::Cancelled => bail!("payment was canceled"),
		}

		// If we have already HTLC VTXOs stored, let's only check if the server sent us the same ones
		if let Some(vtxos) = &lightning_receive.htlc_vtxos {
			debug_assert!({
				let vtxos_by_id = vtxos.iter().map(|v| (v.id(), v)).collect::<HashMap<_, _>>();
				sub.htlc_vtxos.iter().all(|v| {
					match VtxoId::from_slice(v) {
						Ok(id) => vtxos_by_id.contains_key(&id),
						Err(_) => false,
					}
				})
			}, "server sent HTLC VTXOs that we don't have");

			return Ok(lightning_receive)
		}

		let htlc_recv_expiry = current_height + lightning_receive.htlc_recv_cltv_delta as BlockHeight;

		let (keypair, _) = self.derive_store_next_keypair()?;
		let req = protos::PrepareLightningReceiveClaimRequest {
			payment_hash: lightning_receive.payment_hash.to_vec(),
			user_pubkey: keypair.public_key().serialize().to_vec(),
			htlc_recv_expiry: htlc_recv_expiry,
		};
		let res = srv.client.prepare_lightning_receive_claim(req).await
			.context("error preparing lightning receive claim")?.into_inner();
		let vtxos = res.htlc_vtxos.into_iter()
			.map(|b| Vtxo::deserialize(&b))
			.collect::<Result<Vec<_>, _>>()
			.context("invalid htlc vtxos from server")?;

		// sanity check the vtxos
		for vtxo in &vtxos {
			if let VtxoPolicy::ServerHtlcRecv(p) = vtxo.policy() {
				if p.payment_hash != lightning_receive.payment_hash {
					bail!("invalid payment hash on HTLC VTXOs received from server: {}",
						p.payment_hash,
					);
				}
				if p.user_pubkey != keypair.public_key() {
					bail!("invalid pubkey on HTLC VTXOs received from server: {}", p.user_pubkey);
				}
				if p.htlc_expiry < htlc_recv_expiry {
					bail!("HTLC VTXO expiry height is less than requested: Requested {}, received {}", htlc_recv_expiry, p.htlc_expiry);
				}
			} else {
				bail!("invalid HTLC VTXO policy: {:?}", vtxo.policy());
			}
		}

		// check sum match invoice amount
		let invoice_amount = lightning_receive.invoice.amount_milli_satoshis().map(|a| Amount::from_msat_floor(a))
			.expect("ln receive invoice should have amount");
		ensure!(vtxos.iter().map(|v| v.amount()).sum::<Amount>() >= invoice_amount,
			"Server didn't return enough VTXOs to cover invoice amount"
		);

		let vtxos = vtxos.into_iter().map(|v| WalletVtxo {
			vtxo: v.clone(),
			state: VtxoState::Locked,
		}).collect::<Vec<_>>();

		self.db.register_movement(MovementArgs {
			kind: MovementKind::LightningReceive,
			spends: &[],
			receives: &vtxos.iter().map(|v| (&v.vtxo, v.state.clone())).collect::<Vec<_>>(),
			recipients: &[],
			fees: None,
		})?;

		let vtxo_ids = vtxos.iter().map(|v| v.id()).collect::<Vec<_>>();
		self.db.set_lightning_receive_vtxos(payment_hash, &vtxo_ids)?;

		lightning_receive.htlc_vtxos = Some(vtxos);

		Ok(lightning_receive)
	}

	/// Check and claim a Lightning receive
	///
	/// This function checks for an incoming lightning payment with the given [PaymentHash]
	/// and then claims the payment using returned HTLC VTXOs.
	///
	/// # Arguments
	///
	/// * `payment_hash` - The [PaymentHash] of the lightning payment
	/// to check for.
	/// * `wait` - Whether to wait for the payment to be received.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<()>`, which is:
	/// * `Ok(())` if the process completes successfully.
	/// * `Err` if an error occurs at any stage of the operation.
	///
	/// # Remarks
	///
	/// * The payment hash must be from an invoice previously generated using
	///   [Wallet::bolt11_invoice].
	pub async fn check_and_claim_ln_receive(
		&self,
		payment_hash: PaymentHash,
		wait: bool,
	) -> anyhow::Result<()> {
		let receive = self.check_ln_receive(payment_hash, wait).await?;
		self.claim_ln_receive(&receive).await
	}

	/// Check and claim all opened Lightning receive
	///
	/// This function fetches all opened lightning receives and then
	/// concurrently tries to check and claim them
	///
	/// # Arguments
	///
	/// * `wait` - Whether to wait for each payment to be received.
	///
	/// # Returns
	///
	/// Returns an `anyhow::Result<()>`, which is:
	/// * `Ok(())` if the process completes successfully.
	/// * `Err` if an error occurs at any stage of the operation.
	pub async fn check_and_claim_all_open_ln_receives(&self, wait: bool) -> anyhow::Result<()> {
		// Asynchronously attempts to claim all pending receive by converting the list into a stream
		tokio_stream::iter(self.pending_lightning_receives()?)
			.for_each_concurrent(3, |rcv| async move {
				if let Err(e) = self.check_and_claim_ln_receive(rcv.invoice.into(), wait).await {
					error!("Error claiming lightning receive: {}", e);
				}
			}).await;

		Ok(())
	}

	/// Claim all pending lightning receives
	///
	/// This is different from [Wallet::check_and_claim_all_open_ln_receives] in
	/// that it only affect pending lightning receives whose HTLC VTXOs
	/// have already been issued.
	///
	/// Note:
	///   - If an HTLC VTXO cannot be claimed and the htlc expiry is too close,
	///   it will either mark the htlc as cancelled (preimage not revealed) or
	///   mark the vtxo for exit (preimage revealed).
	async fn claim_all_pending_htlc_recvs(&self) -> anyhow::Result<()> {
		let srv = self.require_server()?;
		let tip = self.chain.tip().await?;
		let lightning_receives = self.db.get_all_pending_lightning_receives()?;
		info!("Syncing {} pending lightning receives", lightning_receives.len());

		for lightning_receive in lightning_receives {
			let vtxos = match &lightning_receive.htlc_vtxos {
				Some(vtxos) => vtxos,
				None => continue,
			};

			if let Err(e) = self.claim_ln_receive(&lightning_receive).await {
				error!("Failed to claim pubkey vtxo from htlc vtxo: {}", e);

				let first_vtxo = &vtxos.first().unwrap().vtxo;
				debug_assert!(vtxos.iter().all(|v| {
					v.vtxo.policy() == first_vtxo.policy() && v.vtxo.exit_delta() == first_vtxo.exit_delta()
				}), "all htlc vtxos for the same payment hash should have the same policy and exit delta");

				let vtxo_htlc_expiry = first_vtxo.policy().as_server_htlc_recv()
					.expect("only server htlc recv vtxos can be pending lightning recv").htlc_expiry;

				let safe_exit_margin = first_vtxo.exit_delta() +
					srv.info.htlc_expiry_delta +
					self.config.vtxo_exit_margin;

				if tip > vtxo_htlc_expiry.saturating_sub(safe_exit_margin as BlockHeight) {
					if lightning_receive.preimage_revealed_at.is_some() {
						warn!("HTLC-recv VTXOs are about to expire and preimage has been disclosed, must exit");
						self.exit.write().await.mark_vtxos_for_exit(&vtxos.iter().map(|v| v.vtxo.clone()).collect::<Vec<_>>());
					} else {
						warn!("HTLC-recv VTXOs are about to expire, but preimage has not been disclosed yet, mark htlc as cancelled");
						self.db.register_movement(MovementArgs {
							kind: MovementKind::LightningReceive,
							spends: &vtxos.iter().map(|v| &v.vtxo).collect::<Vec<_>>(),
							receives: &[],
							recipients: &[],
							fees: None,
						})?;
					}
				}
			}
		}

		Ok(())
	}

	/// Same as [Wallet::send_lightning_payment] but instead it pays a [LightningAddress].
	pub async fn send_lnaddr(
		&self,
		addr: &LightningAddress,
		amount: Amount,
		comment: Option<&str>,
	) -> anyhow::Result<(Bolt11Invoice, Preimage)> {
		let invoice = lnurl::lnaddr_invoice(addr, amount, comment).await
			.context("lightning address error")?;
		info!("Attempting to pay invoice {}", invoice);
		let preimage = self.send_lightning_payment(invoice.clone(), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	/// Attempts to pay the given BOLT12 [Offer] using offchain funds.
	pub async fn pay_offer(
		&self,
		offer: Offer,
		amount: Option<Amount>,
	) -> anyhow::Result<(Bolt12Invoice, Preimage)> {
		let mut srv = self.require_server()?;

		let offer_bytes = {
			let mut bytes = Vec::new();
			offer.write(&mut bytes).unwrap();
			bytes
		};

		let req = protos::FetchBolt12InvoiceRequest {
			offer: offer_bytes,
			amount_sat: amount.map(|a| a.to_sat()),
		};

		let resp = srv.client.fetch_bolt12_invoice(req).await?.into_inner();

		let invoice = Bolt12Invoice::try_from(resp.invoice)
			.map_err(|_| anyhow::anyhow!("invalid invoice"))?;

		invoice.validate_issuance(offer)?;

		let preimage = self.send_lightning_payment(invoice.clone(), None).await
			.context("bolt11 payment error")?;
		Ok((invoice, preimage))
	}

	pub fn build_round_onchain_payment_participation(
		&self,
		addr: bitcoin::Address,
		amount: Amount,
	) -> anyhow::Result<RoundParticipation> {
		let srv = self.require_server()?;

		let offb = OffboardRequest {
			script_pubkey: addr.script_pubkey(),
			amount: amount,
		};
		let required_amount = offb.amount + offb.fee(srv.info.offboard_feerate)?;

		let inputs = self.select_vtxos_to_cover(required_amount, None, None)?;

		let change = {
			let input_sum = inputs.iter().map(|v| v.amount()).sum::<Amount>();
			if input_sum < offb.amount {
				bail!("Your balance is too low. Needed: {}, available: {}",
					required_amount, self.balance()?.spendable,
				);
			} else if input_sum <= required_amount + P2TR_DUST {
				info!("No change, emptying wallet.");
				None
			} else {
				let change_amount = input_sum - required_amount;
				let (change_keypair, _) = self.derive_store_next_keypair()?;
				info!("Adding change vtxo for {}", change_amount);
				Some(VtxoRequest {
					amount: change_amount,
					policy: VtxoPolicy::new_pubkey(change_keypair.public_key()),
				})
			}
		};

		Ok(RoundParticipation {
			inputs: inputs,
			outputs: change.into_iter().collect(),
			offboards: vec![offb],
		})
	}

	/// Sends the given [Amount] to an onchain [bitcoin::Address]. This is an in-round operation
	/// which may take a long time to perform.
	pub async fn send_round_onchain_payment(
		&self,
		addr: bitcoin::Address,
		amount: Amount,
	) -> anyhow::Result<RoundStatus> {
		let mut participation = self.build_round_onchain_payment_participation(addr, amount)?;

		if let Err(e) = self.add_should_refresh_vtxos(&mut participation).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(self.participate_round(participation).await?)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[allow(unused)] // just exists for compile check
	async fn send_lightning_payment_argument() {
		//! Check the different possible argument for send_lightning_payment

		let db = Arc::new(SqliteClient::open("").unwrap());
		let w = Wallet::open(
			&"".parse().unwrap(), db, Config::network_default(Network::Regtest),
		).await.unwrap();

		let bolt11 = Bolt11Invoice::from_str("").unwrap();
		w.send_lightning_payment(bolt11, None).await.unwrap();

		let bolt12 = Bolt12Invoice::from_str("").unwrap();
		w.send_lightning_payment(bolt12, None).await.unwrap();

		let string = format!("lnbc1..");
		w.send_lightning_payment(string, None).await.unwrap();

		let strr = "lnbc1..";
		w.send_lightning_payment(strr, None).await.unwrap();

		let invoice = Invoice::Bolt11("".parse().unwrap());
		w.send_lightning_payment(invoice, None).await.unwrap();
	}
}
