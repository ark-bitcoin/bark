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
//! [![Project Status](https://img.shields.io/badge/status-active-brightgreen.svg)](https://gitlab.com/ark-bitcoin/bark)
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
//! We have implemented [`persist::sqlite::SqliteClient`] which is a sane default on most devices
//! (requires the `sqlite` feature). However, it is possible to implement a
//! [BarkPersister] if you have other requirements.
//!
//! The code-snippet below shows how you can create a [Wallet].
//!
//! ```no_run
//! use std::path::PathBuf;
//! use std::sync::Arc;
//! use bark::{Config, onchain, Wallet, OpenWalletArgs, WalletSeed};
//! use bark::lock_manager::memory::MemoryLockManager;
//! use bark::persist::sqlite::SqliteClient;
//!
//! const MNEMONIC_FILE : &str = "mnemonic";
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
//! 	// Create a sqlite database
//! 	let datadir = PathBuf::from("./bark");
//!
//! 	// Generate and seed and store it somewhere
//! 	let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
//! 	tokio::fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await.unwrap();
//! 	let seed = WalletSeed::new_from_mnemonic(network, &mnemonic);
//!
//! 	let wallet = Wallet::open(network, seed, config, OpenWalletArgs {
//! 		datadir: Some(datadir),
//! 		..Default::default()
//! 	}).await.unwrap();
//! }
//! ```
//!
//! ## Opening an existing Ark wallet
//!
//! The [Wallet] can be opened again by providing the [bip39::Mnemonic] and
//! the [BarkPersister] again. Note, that [`persist::sqlite::SqliteClient`] implements the [BarkPersister]-trait.
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use std::path::PathBuf;
//! # use std::str::FromStr;
//! #
//! # use bip39;
//! # use bitcoin::Network;
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, WalletSeed, OpenWalletArgs};
//! # use bark::lock_manager::memory::MemoryLockManager;
//! # use bark::persist::sqlite::SqliteClient;
//! #
//! const MNEMONIC_FILE : &str = "mnemonic";
//!
//! #[tokio::main]
//! async fn main() {
//! 	let datadir = PathBuf::from("./bark");
//! 	let config = Config {
//! 		server_address: String::from("https://ark.signet.2nd.dev"),
//! 		esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
//! 		..Config::network_default(Network::Signet)
//! 	};
//!
//! 	let mnemonic_str = fs::read_to_string(datadir.join(MNEMONIC_FILE)).await.unwrap();
//! 	let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! 	let seed = WalletSeed::new_from_mnemonic(Network::Signet, &mnemonic);
//! 	let wallet = Wallet::open(Network::Signet, seed, config, OpenWalletArgs {
//! 		datadir: Some(datadir),
//! 		..Default::default()
//! 	}).await.unwrap();
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
//! # use bitcoin::Network;
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, OpenWalletArgs, WalletSeed};
//! # use bark::lock_manager::memory::MemoryLockManager;
//! # use bark::persist::sqlite::SqliteClient;
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! #
//! # async fn get_wallet() -> Wallet {
//! #   let datadir = PathBuf::from("./bark");
//! #
//! #   let mnemonic_str = fs::read_to_string(datadir.join(MNEMONIC_FILE)).await.unwrap();
//! #   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! #   let seed = WalletSeed::new_from_mnemonic(Network::Signet, &mnemonic);
//! #
//! #   let config = Config::network_default(bitcoin::Network::Signet);
//! #   Wallet::open(Network::Signet, seed, config, OpenWalletArgs {
//! #   	datadir: Some(datadir),
//! #   	..Default::default()
//! #   }).await.unwrap()
//! # }
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
//! # use bitcoin::Network;
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, OpenWalletArgs, WalletSeed};
//! # use bark::lock_manager::memory::MemoryLockManager;
//! # use bark::persist::sqlite::SqliteClient;
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! #
//! # async fn get_wallet() -> Wallet {
//! #   let datadir = PathBuf::from("./bark");
//! #
//! #   let mnemonic_str = fs::read_to_string(datadir.join(MNEMONIC_FILE)).await.unwrap();
//! #   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! #   let seed = WalletSeed::new_from_mnemonic(Network::Signet, &mnemonic);
//! #
//! #   let config = Config::network_default(bitcoin::Network::Signet);
//! #   Wallet::open(Network::Signet, seed, config, OpenWalletArgs {
//! #   	datadir: Some(datadir),
//! #   	..Default::default()
//! #   }).await.unwrap()
//! # }
//! #
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//! 	let mut wallet = get_wallet().await;
//!
//! 	// The vtxo's command doesn't sync your wallet
//! 	// When you're not running the daemon, make sure your app is synced
//! 	// before inspecting the wallet
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
//! # use bitcoin::Network;
//! # use tokio::fs;
//! #
//! # use bark::{Config, Wallet, OpenWalletArgs, WalletSeed};
//! # use bark::lock_manager::memory::MemoryLockManager;
//! # use bark::persist::sqlite::SqliteClient;
//! #
//! # const MNEMONIC_FILE : &str = "mnemonic";
//! #
//! # async fn get_wallet() -> Wallet {
//! #   let datadir = PathBuf::from("./bark");
//! #
//! #   let mnemonic_str = fs::read_to_string(datadir.join(MNEMONIC_FILE)).await.unwrap();
//! #   let mnemonic = bip39::Mnemonic::from_str(&mnemonic_str).unwrap();
//! #   let seed = WalletSeed::new_from_mnemonic(Network::Signet, &mnemonic);
//! #
//! #   let config = Config::network_default(bitcoin::Network::Signet);
//! #   Wallet::open(Network::Signet, seed, config, OpenWalletArgs {
//! #   	datadir: Some(datadir),
//! #   	..Default::default()
//! #   }).await.unwrap()
//! # }
//! #
//! use bark::vtxo::RefreshStrategy;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//! 	let wallet = get_wallet().await;
//!
//! 	// Select all vtxos that refresh soon
//! 	let tip = wallet.chain().tip().await?;
//! 	let fee_rate = wallet.chain().fee_rates().await.fast;
//! 	let strategy = RefreshStrategy::must_refresh(&wallet, tip, fee_rate);
//!
//! 	let vtxos = wallet.spendable_vtxos_with(&strategy).await?;
//!		wallet.refresh_vtxos(vtxos).await?;
//! 	Ok(())
//! }
//! ```

#[cfg(all(any(target_os = "android", target_os = "ios"), feature = "tls-native-roots"))]
compile_error!("feature `tls-native-roots` can't be used on Android or iOS, use `tls-webpki-roots` instead");

pub extern crate ark;

pub extern crate bip39;
pub extern crate lightning_invoice;
pub extern crate lnurl as lnurllib;

#[macro_use] extern crate anyhow;
#[macro_use] extern crate async_trait;
#[macro_use] extern crate serde;

pub mod actions;
pub mod chain;
pub mod exit;
pub mod movement;
pub mod onchain;
pub mod payment_request;
pub mod persist;
pub mod round;
pub mod subsystem;
pub mod vtxo;

pub mod lock_manager;

mod arkoor;
mod board;
mod config;
mod daemon;
mod fees;
mod lightning;
mod mailbox;
mod notification;
mod offboard;
#[cfg(feature = "socks5-proxy")]
mod proxy;
mod psbtext;
mod utils;

pub use self::arkoor::{ArkoorCreateResult, ArkoorAddressError};
pub use self::config::{BarkNetwork, Config};
pub use self::daemon::DaemonHandle;
pub use self::fees::FeeEstimate;
pub use self::notification::{WalletNotification, NotificationStream};
pub use self::vtxo::WalletVtxo;
pub use self::utils::time;

use std::borrow::Cow;
use std::collections::HashSet;
use std::iter;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use bip39::Mnemonic;
use bitcoin::{Amount, Network, OutPoint};
use bitcoin::bip32::{self, ChildNumber, Fingerprint};
use bitcoin::secp256k1::{self, Keypair, PublicKey};
use futures::stream::FuturesUnordered;
use log::{debug, error, info, trace, warn};
use tokio_stream::StreamExt;

use ark::{ArkInfo, ProtocolEncoding, Vtxo, VtxoId, VtxoPolicy, VtxoRequest};
use ark::address::VtxoDelivery;
use ark::fees::{validate_and_subtract_fee_min_dust, VtxoFeeInfo};
use ark::rounds::{RoundAttempt, RoundEvent};
use ark::vtxo::{Full, PubkeyVtxoPolicy, VtxoRef};
use ark::vtxo::policy::signing::VtxoSigner;
use bitcoin_ext::{BlockHeight, P2TR_DUST, TxStatus};
use server_rpc::{protos, ServerConnection};
use server_rpc::client::{ConnectError, CreateEndpointError};

use crate::chain::{ChainSource, ChainSourceSpec};
use crate::exit::Exit;
use crate::lock_manager::LockManager;
use crate::movement::{Movement, MovementId, PaymentMethod};
use crate::movement::manager::MovementManager;
use crate::notification::NotificationDispatch;
use crate::onchain::{ExitUnilaterally, PreparePsbt, SignPsbt, Utxo};
use crate::onchain::DaemonizableOnchainWallet;
use crate::persist::BarkPersister;
use crate::persist::models::{RoundStateId, StoredRoundState, Unlocked};
#[cfg(feature = "socks5-proxy")]
use crate::proxy::proxy_for_url;
use crate::round::{RoundParticipation, RoundSecretNonces, RoundStatus};
use crate::subsystem::RoundMovement;
use crate::utils::rejected_vtxos_from_error;
use crate::vtxo::{FilterVtxos, RefreshStrategy, VtxoFilter, VtxoStateKind};

#[cfg(all(feature = "wasm-web", feature = "socks5-proxy"))]
compile_error!("features `wasm-web` does not support feature `socks5-proxy");

#[cfg(all(feature = "wasm-web", feature = "bitcoind-rpc"))]
compile_error!("`wasm-web` does not support the `bitcoind-rpc` feature");

/// Derivation index for Bark usage
const BARK_PURPOSE_INDEX: u32 = 350;
/// Derivation index used to generate keypairs to sign VTXOs
const VTXO_KEYS_INDEX: u32 = 0;
/// Derivation index used to generate keypair for the mailbox
const MAILBOX_KEY_INDEX: u32 = 1;
/// Derivation index used to generate keypair for the recovery mailbox
const RECOVERY_MAILBOX_KEY_INDEX: u32 = 2;
const MISSING_SERVER_TRANSPORT_HELP: &str =
	"This build of bark-wallet does not include an Ark server transport backend. Enable feature `bark-wallet/native` or `bark-wallet/wasm-web` to use server-backed wallet functionality.";

/// The timeout value to use for streaming subscribe requests to the Ark server
const SUBSCRIBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(60 * 60);

lazy_static::lazy_static! {
	/// Global secp context.
	static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

/// Log that the server public key has changed.
///
/// Recommends that the user perform an emergency exit to recover their
/// funds on-chain, since a rotated server pubkey makes the original VTXO
/// spend/exit conditions unreachable.
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

/// Log that the server mailbox pubkey has changed.
fn log_server_mailbox_pubkey_changed_error(expected: PublicKey, got: PublicKey) {
	error!(
	    "
Server mailbox public key has changed!

The Ark server's mailbox public key is different from the one stored when this
wallet was created. This typically happens when:

	- The server operator has rotated their keys
	- You are connecting to a different server
	- The server has been replaced

For safety, this wallet will not connect to the server until you resolve this.

Unlike a server pubkey change, your VTXOs are not at risk - the mailbox pubkey
only affects address receive semantics. Any Ark addresses you previously
shared will stop receiving new payments; you will need to share new addresses
after reconnecting.

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
	/// Coins held in VTXOs whose unilateral exit chain has confirmed onchain but which
	/// haven't yet been drained back to the onchain wallet. While in this state the
	/// VTXOs are [`vtxo::VtxoStateKind::Exited`] and unusable in the Ark protocol; the
	/// drain transaction moves them to spendable onchain output.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

	/// The server's mailbox public key.
	///
	/// Stored so that Ark addresses can be generated without a live
	/// connection to the Ark server. `None` indicates a wallet created
	/// before this field was added; the value is populated on the first
	/// successful handshake. If the key changes, the wallet refuses to
	/// connect until the user resolves the rotation.
	pub server_mailbox_pubkey: Option<PublicKey>,
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
	/// Create a new [WalletSeed] from a given BIP-32 master seed
	pub fn new_from_seed(network: Network, seed: &[u8; 64]) -> Self {
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

	/// Create a new [WalletSeed] from a given BIP-39 [Mnemonic]
	pub fn new_from_mnemonic(network: Network, mnemonic: &Mnemonic) -> Self {
		Self::new_from_seed(network, &mnemonic.to_seed(""))
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

	fn to_recovery_mailbox_keypair(&self) -> Keypair {
		let mailbox_path = [ChildNumber::from_hardened_idx(RECOVERY_MAILBOX_KEY_INDEX).unwrap()];
		self.master.derive_priv(&SECP, &mailbox_path).unwrap().to_keypair(&SECP)
	}
}

/// Additional arguments for the [Wallet::open] function
pub struct OpenWalletArgs {
	/// Whether to run the background daemon
	///
	/// When disabled, you must manually call `Wallet::sync` to sync the wallet.
	///
	/// Default: true
	pub run_daemon: bool,

	/// The data directory to use for this wallet
	///
	/// This field can be used under most platforms as an alternative to
	/// providing the `persister` and `lock_manager` fields.
	///
	/// This field is ignored if `persister` and `lock_manager` are provided
	/// or for the wasm32 platform.
	///
	/// Default: none
	pub datadir: Option<PathBuf>,

	/// The persister to use for this wallet
	///
	/// Default: returned by [`crate::persist::platform_default`]
	pub persister: Option<Arc<dyn BarkPersister>>,

	/// The lock manager to use for this wallet
	///
	/// Default: returned by [`crate::lock_manager::platform_default`]
	///
	/// On some platforms (linux, macos, windows) the default lock manager
	/// requires a datadir be provided.
	pub lock_manager: Option<Box<dyn LockManager>>,

	/// The onchain wallet to use, if any
	///
	/// Default: none
	pub onchain: Option<Arc<tokio::sync::RwLock<dyn DaemonizableOnchainWallet>>>,

	/// Whether to create a new wallet if no wallet exists
	///
	///  Default: true
	pub create_if_not_exists: bool,

	/// Whether to create a new wallet even if the Ark server cannot be reached
	///
	/// Default: false
	pub create_without_server: bool,
}

impl Default for OpenWalletArgs {
	fn default() -> Self {
	    Self {
			run_daemon: true,
			onchain: None,
			datadir: None,
			persister: None,
			lock_manager: None,
			create_if_not_exists: true,
			create_without_server: false,
		}
	}
}

struct WalletInner {
	/// The chain source the wallet is connected to
	chain: Arc<ChainSource>,

	/// Exit subsystem handling unilateral exits and on-chain reconciliation outside Ark rounds.
	exit: Exit,

	/// Allows easy creation of and management of wallet fund movements.
	movements: Arc<MovementManager>,

	/// Dispatch for wallet notifications
	notifications: NotificationDispatch,

	/// Active runtime configuration for networking, fees, policies and thresholds.
	config: Config,

	/// Persistence backend for wallet state (keys metadata, VTXOs, movements, round state, etc.).
	db: Arc<dyn BarkPersister>,

	/// Coordinates access to the wallet's protected resources. The caller
	/// picks a backend whose enforcement scope matches how the wallet is
	/// deployed; see [`crate::lock_manager`].
	lock_manager: Box<dyn LockManager>,

	/// Deterministic seed material used to generate wallet keypairs.
	seed: WalletSeed,

	/// Live connection to an Ark server for round participation and synchronization.
	///
	/// Lazily initialised on first use via [`Wallet::require_server`]. A
	/// [`OnceCell`] is the right primitive here: concurrent callers on a
	/// cold cell all await the same in-flight `connect_to_server` future
	/// instead of each opening a fresh gRPC channel.
	server: tokio::sync::OnceCell<ServerConnection>,

	/// A handle to the currently running daemon, if any.
	daemon: parking_lot::Mutex<Option<DaemonHandle>>,

	/// The last chain tip at which we scanned spendable VTXOs for on-chain (force) exits.
	/// The scan is skipped while the tip is unchanged, since a VTXO's on-chain status can
	/// only change across blocks.
	last_force_exit_scan_tip: tokio::sync::Mutex<Option<BlockHeight>>,

	/// In-memory MuSig2 secret cosign nonces for in-flight round attempts.
	/// See [`RoundSecretNonces`].
	pub(crate) round_secret_nonces: RoundSecretNonces,
}

/// The central entry point for using this library as an Ark wallet.
///
/// Note that a [Wallet] instance can freely be [Clone]'ed to refer to the same
/// wallet.
///
/// Overview
/// - Wallet encapsulates the complete Ark client implementation:
///   - address generation (Ark addresses/keys)
///     - [Wallet::new_address],
///     - [Wallet::new_address_with_index],
///     - [Wallet::peek_address],
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
///
/// A [Wallet] is opened or created using a mnemonic and a backend implementing [BarkPersister].
/// The [Wallet::open] function allows for opening and creating a wallet if it doesn't exist yet.
/// Check out the documentation on [OpenWalletArgs] for all optional arguments.
///
/// Example
/// ```no_run
/// use std::path::PathBuf;
/// use std::sync::Arc;
/// use tokio::fs;
/// use bark::{Config, onchain, Wallet, OpenWalletArgs, WalletSeed};
/// use bark::lock_manager::memory::MemoryLockManager;
/// use bark::persist::sqlite::SqliteClient;
///
/// const MNEMONIC_FILE : &str = "mnemonic";
///
/// #[tokio::main]
/// async fn main() {
/// 	// Pick the bitcoin network that will be used
/// 	let network = bitcoin::Network::Signet;
///
/// 	// Configure the wallet
/// 	let config = Config {
/// 		server_address: String::from("https://ark.signet.2nd.dev"),
/// 		esplora_address: Some(String::from("https://esplora.signet.2nd.dev")),
/// 		..Config::network_default(network)
/// 	};
///
/// 	// Create a sqlite database
/// 	let datadir = PathBuf::from("./bark");
///
/// 	// Generate and seed and store it somewhere
/// 	let mnemonic = bip39::Mnemonic::generate(12).expect("12 is valid");
/// 	fs::write(datadir.join(MNEMONIC_FILE), mnemonic.to_string().as_bytes()).await.unwrap();
/// 	let seed = WalletSeed::new_from_mnemonic(network, &mnemonic);
///
/// 	let wallet = Wallet::open(network, seed, config, OpenWalletArgs {
/// 		datadir: Some(datadir),
/// 		..Default::default()
/// 	}).await.unwrap();
/// }
/// ```


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
/// wallet.sync_exits().await?;
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
/// wallet.exit_mgr().sync_no_progress().await?;
/// wallet.exit_mgr().progress_exits_with_bdk(&wallet, &mut onchain_wallet, None).await?;
///
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Wallet {
	inner: Arc<WalletInner>,
}

impl Wallet {
	pub async fn network(&self) -> anyhow::Result<Network> {
		Ok(self.properties().await?.network)
	}

	/// Access the server's chain source
	pub fn chain(&self) -> &Arc<ChainSource> {
		&self.inner.chain
	}

	/// Access the exit manager
	pub fn exit_mgr(&self) -> &Exit {
		&self.inner.exit
	}

	/// Access the movements manager
	pub fn movements_mgr(&self) -> &MovementManager {
		&self.inner.movements
	}

	/// Peek at the keypair directly after currently last revealed one,
	/// together with its index, without storing it.
	pub async fn peek_next_keypair(&self) -> anyhow::Result<(Keypair, u32)> {
		let last_revealed = self.inner.db.get_last_vtxo_key_index().await?;

		let index = last_revealed.map(|i| i + 1).unwrap_or(u32::MIN);
		let keypair = self.inner.seed.derive_vtxo_keypair(index);

		Ok((keypair, index))
	}

	/// Derive and store the keypair directly after currently last revealed one,
	/// together with its index.
	pub async fn derive_store_next_keypair(&self) -> anyhow::Result<(Keypair, u32)> {
		let (keypair, index) = self.peek_next_keypair().await?;
		self.inner.db.store_vtxo_key(index, keypair.public_key()).await?;
		Ok((keypair, index))
	}

	#[deprecated(note = "use peek_keypair instead")]
	pub async fn peak_keypair(&self, index: u32) -> anyhow::Result<Keypair> {
		self.peek_keypair(index).await
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
	pub async fn peek_keypair(&self, index: u32) -> anyhow::Result<Keypair> {
		let keypair = self.inner.seed.derive_vtxo_keypair(index);
		if self.inner.db.get_public_key_idx(&keypair.public_key()).await?.is_some() {
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
		if let Some(index) = self.inner.db.get_public_key_idx(&public_key).await? {
			Ok(Some((index, self.inner.seed.derive_vtxo_keypair(index))))
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
		let bare_vtxo = match vtxo.as_bare_vtxo() {
			Some(bare) => bare,
			None => Cow::Owned(self.get_vtxo_by_id(vtxo.vtxo_id()).await?.vtxo),
		};
		let pubkey = self.find_signable_clause(&bare_vtxo).await
			.context("VTXO is not signable by wallet")?
			.pubkey();
		let idx = self.inner.db.get_public_key_idx(&pubkey).await?
			.context("VTXO key not found")?;
		Ok(self.inner.seed.derive_vtxo_keypair(idx))
	}

	#[deprecated(note = "use peek_address instead")]
	pub async fn peak_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		self.peek_address(index).await
	}

	/// Peek for an [ark::Address] at the given key index.
	///
	/// May return an error if the address at the given index has not been derived yet.
	pub async fn peek_address(&self, index: u32) -> anyhow::Result<ark::Address> {
		let properties = self.properties().await?;
		let network = properties.network;
		let keypair = self.peek_keypair(index).await?;
		let mailbox = self.mailbox_identifier();


		let (server_pubkey, mailbox_pubkey) =
			if let (Some(spk), Some(mpk)) = (properties.server_pubkey, properties.server_mailbox_pubkey) {
				(spk, mpk)
			} else {
				let (_, ark_info) = self.require_server().await?;
				(ark_info.server_pubkey, ark_info.mailbox_pubkey)
			};

		Ok(ark::Address::builder()
			.testnet(network != bitcoin::Network::Bitcoin)
			.server_pubkey(server_pubkey)
			.pubkey_policy(keypair.public_key())
			.mailbox(mailbox_pubkey, mailbox, &keypair)
			.expect("Failed to assign mailbox")
			.into_address().unwrap())
	}

	/// Generate a new [ark::Address] and returns the index of the key used to create it.
	///
	/// This derives and stores the keypair directly after currently last revealed one.
	pub async fn new_address_with_index(&self) -> anyhow::Result<(ark::Address, u32)> {
		let (_, index) = self.derive_store_next_keypair().await?;
		let addr = self.peek_address(index).await?;
		Ok((addr, index))
	}

	/// Generate a new mailbox [ark::Address].
	pub async fn new_address(&self) -> anyhow::Result<ark::Address> {
		let (addr, _) = self.new_address_with_index().await?;
		Ok(addr)
	}

	/// Create a new wallet
	///
	/// This function simply initiates a new wallet; use [Wallet::open] to open
	/// it afterwards. You can also call [Wallet::open] with `create_if_not_exists`
	/// set to true to avoid having to call this function.
	///
	/// `lock_manager` coordinates access to the wallet's protected resources. Pick a backend
	/// whose enforcement scope matches how the wallet is deployed — see [`crate::lock_manager`].
	pub async fn create(
		network: Network,
		seed: &WalletSeed,
		config: &Config,
		db: &dyn BarkPersister,
		lock_manager: &dyn LockManager,
		allow_unreachable_server: bool,
	) -> anyhow::Result<()> {
		trace!("Config: {:?}", config);

		let wallet_fingerprint = seed.fingerprint();

		// Block concurrent creators against the same locking universe. A
		// short timeout is fine: if a sibling process wins the race they
		// will have committed the wallet by the time we'd time out, and
		// the `read_properties` check below catches that case cleanly.
		let create_guard = lock_manager.lock(
			&format!("{}.create", wallet_fingerprint),
			Duration::from_secs(5),
		).await.context("wallet initialization already in progress")?;

		if let Some(existing) = db.read_properties().await? {
			trace!("Existing config: {:?}", existing);
			bail!("cannot overwrite already existing config")
		}

		// Try to connect to the server and get its pubkey
		let (server_pubkey, mailbox_pubkey) = match Self::connect_to_server(&config, network).await {
			Ok(conn) => {
				let ark_info = conn.ark_info().await;
				(Some(ark_info.server_pubkey), Some(ark_info.mailbox_pubkey))
			},
			Err(_) if allow_unreachable_server => (None, None),
			Err(err) => {
				bail!("Failed to connect to provided server: {:#}", err);
			},
		};

		let properties = WalletProperties {
			network,
			fingerprint: wallet_fingerprint,
			server_pubkey,
			server_mailbox_pubkey: mailbox_pubkey,
		};

		// write the config to db
		db.init_wallet(&properties).await.context("cannot init wallet in the database")?;
		info!("Created wallet with fingerprint: {}", wallet_fingerprint);
		if let Some(pk) = server_pubkey {
			info!("Stored server pubkey: {}", pk);
		}

		// The wallet exists from this point on — drop the creation lock
		// so another process is free to open it.
		drop(create_guard);

		Ok(())
	}

	/// Open an existing wallet or create one if `options.create_if_not_exists` is true
	pub async fn open(
		network: Network,
		seed: WalletSeed,
		config: Config,
		args: OpenWalletArgs,
	) -> anyhow::Result<Wallet> {
		let fingerprint = seed.fingerprint();
		let lock_manager = if let Some(lm) = args.lock_manager {
			lm
		} else {
			crate::lock_manager::platform_default(args.datadir.as_ref(), Some(fingerprint))
				.context("failed to instantiate platform default lock manager")?
		};

		let db = if let Some(db) = args.persister {
			db
		} else {
			if let Some(ref datadir) = args.datadir {
				#[cfg(not(target_arch = "wasm32"))]
				if !datadir.exists() && args.create_if_not_exists {
					tokio::fs::create_dir_all(datadir).await.with_context(|| format!(
						"failed to create datadir at {}", datadir.display(),
					))?;
				}
			}
			crate::persist::platform_default(args.datadir.as_ref(), Some(fingerprint)).await
				.context("failed to instantiate platform default persister")?
		};

		let properties = if let Some(p) = db.read_properties().await? {
			p
		} else if args.create_if_not_exists {
			Self::create(
				network, &seed, &config, &*db, &*lock_manager, args.create_without_server,
			).await.context("error creating new wallet")?;
			db.read_properties().await?
				.context("create failed: no wallet properties after Wallet::create was called")?
		} else {
			bail!("wallet does not exist; use Wallet::create or \
				set options.create_if_not_exists to true");
		};

		if properties.fingerprint != fingerprint {
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

		#[cfg(feature = "socks5-proxy")]
		let chain_proxy = proxy_for_url(&config.socks5_proxy, chain_source.url())?;
		let chain_source_client = ChainSource::new(
			chain_source, properties.network, config.fallback_fee_rate,
			#[cfg(feature = "socks5-proxy")] chain_proxy.as_deref(),
		).await?;
		let chain = Arc::new(chain_source_client);
		chain.require_version().await
			.context("provided chain source doesn't meet version requirement")?;

		let server = tokio::sync::OnceCell::new();

		let notifications = NotificationDispatch::new();
		let movements = Arc::new(MovementManager::new(db.clone(), notifications.clone()));
		let exit = Exit::new(db.clone(), chain.clone(), movements.clone()).await?;

		let ret = Wallet { inner: Arc::new(WalletInner {
			config, db, lock_manager, seed, exit, movements, notifications, server, chain,
			daemon: parking_lot::Mutex::new(None),
			last_force_exit_scan_tip: tokio::sync::Mutex::new(None),
			round_secret_nonces: RoundSecretNonces::new(),
		})};

		ret.inner.exit.load().await
			.context("error loading exit system after opening wallet")?;

		if args.run_daemon {
			ret.start_daemon(args.onchain)
				.context("failed to start daemon after opening wallet")?;
		}

		Ok(ret)
	}

	/// Returns the config used to create/load the bark [Wallet].
	pub fn config(&self) -> &Config {
		&self.inner.config
	}

	/// Retrieves the [WalletProperties] of the current bark [Wallet].
	pub async fn properties(&self) -> anyhow::Result<WalletProperties> {
		let properties = self.inner.db.read_properties().await?.context("Wallet is not initialised")?;
		Ok(properties)
	}

	/// Returns the fingerprint of the wallet.
	pub fn fingerprint(&self) -> Fingerprint {
		self.inner.seed.fingerprint()
	}

	async fn connect_to_server(
		config: &Config,
		network: Network,
	) -> anyhow::Result<ServerConnection> {
		let server_address = crate::utils::url_with_default_https_scheme(&config.server_address);
		let mut builder = ServerConnection::builder()
			.address(&server_address)
			.network(network);

		#[cfg(feature = "socks5-proxy")]
		if let Some(proxy) = proxy_for_url(&config.socks5_proxy, &server_address)? {
			builder = builder.proxy(&proxy)
		}

		if let Some(ref token) = config.server_access_token {
			builder = builder.access_token(token);
		}

		if let Some(ref ua) = config.user_agent {
			builder = builder.user_agent(ua);
		}

		builder.connect().await.map_err(wrap_server_connect_error)
			.context("Failed to connect to Ark server")
	}

	async fn require_server(&self) -> anyhow::Result<(ServerConnection, ArkInfo)> {
		// Connect lazily if not yet connected. `get_or_try_init` ensures
		// concurrent callers on a cold cell all await the same in-flight
		// connect future instead of each opening a fresh gRPC channel.
		let conn = self.inner.server.get_or_try_init(|| async {
			let network = self.properties().await?.network;
			Self::connect_to_server(&self.inner.config, network).await
				.context("You should be connected to Ark server to perform this action")
		}).await?.clone();

		let ark_info = conn.ark_info().await;
		self.check_and_store_server_keys(&ark_info).await?;

		Ok((conn, ark_info))
	}

	pub async fn refresh_server(&self) -> anyhow::Result<()> {
		// If the cell is still cold, initialise it with a fresh connection.
		// If it is already initialised, run a heartbeat against the existing
		// one — `OnceCell` does not support replacing a stored value, but
		// `ServerConnection` is built around a tonic `Channel` which
		// transparently reconnects, so we don't need to swap it.
		let srv = self.inner.server.get_or_try_init(|| async {
			let properties = self.properties().await?;
			Self::connect_to_server(&self.inner.config, properties.network).await
				.map_err(anyhow::Error::from)
		}).await?;

		srv.check_connection().await?;
		let ark_info = srv.ark_info().await;
		ark_info.fees.validate().context("invalid fee schedule")?;
		self.check_and_store_server_keys(&ark_info).await?;

		Ok(())
	}

	/// Validate that the server's public keys match what we have stored,
	/// and persist them if this is the first time connecting after an upgrade.
	///
	/// Returns an error (via `bail!`) if either the server pubkey or mailbox
	/// pubkey differs from the stored value; callers must not proceed with
	/// server operations on error.
	async fn check_and_store_server_keys(&self, ark_info: &ArkInfo) -> anyhow::Result<()> {
		let properties = self.properties().await?;

		if let Some(stored_pubkey) = properties.server_pubkey {
			if stored_pubkey != ark_info.server_pubkey {
				log_server_pubkey_changed_error(stored_pubkey, ark_info.server_pubkey);
				bail!("Server public key has changed. You should exit all your VTXOs!");
			}
		} else {
			self.inner.db.set_server_pubkey(ark_info.server_pubkey).await?;
			info!("Stored server pubkey for existing wallet: {}", ark_info.server_pubkey);
		}

		if let Some(stored_mailbox_pubkey) = properties.server_mailbox_pubkey {
			if stored_mailbox_pubkey != ark_info.mailbox_pubkey {
				log_server_mailbox_pubkey_changed_error(stored_mailbox_pubkey, ark_info.mailbox_pubkey);
				bail!("Server mailbox public key has changed.");
			}
		} else {
			self.inner.db.set_server_mailbox_pubkey(ark_info.mailbox_pubkey).await?;
			info!("Stored server mailbox pubkey for existing wallet: {}", ark_info.mailbox_pubkey);
		}

		Ok(())
	}

	/// Return [ArkInfo] fetched on last handshake with the Ark server
	pub async fn ark_info(&self) -> anyhow::Result<Option<ArkInfo>> {
		match self.inner.server.get() {
			Some(srv) => Ok(Some(srv.ark_info().await)),
			None => Ok(None),
		}
	}

	/// Return [ArkInfo], connecting lazily if not yet connected.
	///
	/// Errors if the server cannot be reached or if the server's pubkey
	/// or mailbox pubkey no longer matches what was stored at wallet
	/// creation.
	pub async fn require_ark_info(&self) -> anyhow::Result<ArkInfo> {
		let (_, ark_info) = self.require_server().await?;
		Ok(ark_info)
	}

	/// Return the [Balance] of the wallet.
	///
	/// When not running the daemon, make sure you sync before calling this method.
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

		let pending_exit = self.exit_mgr().try_pending_total();

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
	pub async fn validate_vtxo(&self, vtxo: &Vtxo<Full>) -> anyhow::Result<()> {
		let tx = self.inner.chain.get_tx(&vtxo.chain_anchor().txid).await
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
	pub async fn import_vtxo(&self, vtxo: &Vtxo<Full>) -> anyhow::Result<()> {
		if self.inner.db.get_wallet_vtxo(vtxo.id()).await?.is_some() {
			info!("VTXO {} already exists in wallet, skipping import", vtxo.id());
			return Ok(());
		}

		self.validate_vtxo(vtxo).await.context("VTXO validation failed")?;

		if self.find_signable_clause(vtxo).await.is_none() {
			bail!("VTXO {} is not owned by this wallet (no signable clause found)", vtxo.id());
		}

		let current_height = self.inner.chain.tip().await?;
		if vtxo.expiry_height() <= current_height {
			bail!("Vtxo {} has expired", vtxo.id());
		}

		self.store_spendable_vtxos([vtxo]).await.context("failed to store imported VTXO")?;

		info!("Successfully imported VTXO {}", vtxo.id());
		Ok(())
	}

	/// Retrieves the full state of a [Vtxo] for a given [VtxoId] if it exists in the database.
	pub async fn get_vtxo_by_id(&self, vtxo_id: VtxoId) -> anyhow::Result<WalletVtxo> {
		let vtxo = self.inner.db.get_wallet_vtxo(vtxo_id).await
			.with_context(|| format!("Error when querying vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))?;
		Ok(vtxo)
	}

	/// Hydrate a VTXO into its full form, including the unilateral exit chain.
	///
	/// [Wallet::get_vtxo_by_id] returns the bare form ([WalletVtxo] holds
	/// [Vtxo<ark::vtxo::Bare>]). This method reads the genesis chain from the
	/// database and reassembles the full VTXO. Use it from external SDK
	/// callers that need the chain (e.g. to feed into [ArkoorPackageBuilder]
	/// or [Wallet::register_vtxo_transactions_with_server]).
	pub async fn get_full_vtxo(&self, vtxo_id: VtxoId) -> anyhow::Result<Vtxo<Full>> {
		self.inner.db.get_full_vtxo(vtxo_id).await
			.with_context(|| format!("Error when querying full vtxo {} in database", vtxo_id))?
			.with_context(|| format!("The VTXO with id {} cannot be found", vtxo_id))
	}

	/// Similar to [Wallet::get_full_vtxo] but it retrieves the full variant of each given VTXO.
	pub async fn get_full_vtxos<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Vec<Vtxo<Full>>> {
		let ids = vtxos.into_iter().map(|v| v.vtxo_id()).collect::<Vec<_>>();
		self.inner.db.get_full_vtxos(&ids).await
			.with_context(||
				format!("Error when querying full vtxos in database with IDs: {:?}", ids)
			)
	}

	/// Fetches all movements ordered from newest to oldest.
	#[deprecated(since="0.1.0-beta.5", note = "Use Wallet::history instead")]
	pub async fn movements(&self) -> anyhow::Result<Vec<Movement>> {
		self.history().await
	}

	/// Fetches all wallet fund movements ordered from newest to oldest.
	pub async fn history(&self) -> anyhow::Result<Vec<Movement>> {
		Ok(self.inner.db.get_all_movements().await?)
	}

	/// Applies an [RFC 7396](https://www.rfc-editor.org/rfc/rfc7396) JSON Merge Patch to the
	/// metadata of a movement.
	///
	/// ```no_run
	/// # use serde_json::json;
	/// # async fn example(
	/// #     wallet: &bark::Wallet,
	/// #     id: bark::movement::MovementId,
	/// # ) -> anyhow::Result<()> {
	/// // Add or overwrite a key.
	/// wallet.update_history_metadata(id, &json!({"note": "refund issued"})).await?;
	///
	/// // Delete a key (null means remove).
	/// wallet.update_history_metadata(id, &json!({"note": null})).await?;
	///
	/// // Nested merge.
	/// wallet.update_history_metadata(id, &json!({"counterparty": {"name": "Alice"}})).await?;
	/// # Ok(()) }
	/// ```
	pub async fn update_history_metadata(
		&self,
		movement_id: MovementId,
		patch: &serde_json::Value,
	) -> anyhow::Result<()> {
		self.inner.movements.patch_metadata(movement_id, patch).await?;
		Ok(())
	}

	/// Query the wallet history by the given payment method
	pub async fn history_by_payment_method(
		&self,
		payment_method: &PaymentMethod,
	) -> anyhow::Result<Vec<Movement>> {
		let mut ret = self.inner.db.get_movements_by_payment_method(payment_method).await?;
		ret.sort_by_key(|m| m.id);
		Ok(ret)
	}

	/// Returns all VTXOs from the database.
	pub async fn all_vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.inner.db.get_all_vtxos().await?)
	}

	/// Returns all not spent vtxos
	pub async fn vtxos(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		Ok(self.inner.db.get_vtxos_by_state(&VtxoStateKind::UNSPENT_STATES).await?)
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
		let expiry = self.inner.chain.tip().await? + threshold;
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

		// First try progress any rounds that exist, best effort.
		let rounds = self.progress_pending_rounds(None).await;
		if let Err(e) = rounds.as_ref() {
			warn!("Error progressing pending rounds: {:#}", e);
		}

		// Then if there are still some participations open, try to cancel them.
		let states = self.inner.db.get_pending_round_state_ids().await?;
		for id in states {
			debug!("Cancelling pending round participation {}", id);
			let mut state = match self.lock_wait_round_state(id).await {
				Ok(Some(s)) => s,
				Ok(None) => continue, // round disappeared, not our problem
				Err(e) => {
					warn!("Failed to lock round state with id {}: {:#}", id, e);
					continue;
				}
			};
			if let Err(e) = state.state_mut().try_cancel(self).await {
				warn!("Error cancelling pending round: {:#}", e);
			}
		}

		// And then call refresh so that we can start again.
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
		let exit_sync = self.sync_exits().await;
		if let Err(e) = exit_sync.as_ref() {
			warn!("Error syncing exits: {:#}", e);
		}
		let exit_progress = self.exit_mgr().progress_exits_with_bdk(self, onchain, None).await;
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
		let exit_sync = self.sync_exits().await;
		if let Err(e) = exit_sync.as_ref() {
			warn!("Error syncing exits: {:#}", e);
		}
		let exit_progress = self.exit_mgr().progress_exits_with_bdk(self, onchain, None).await;
		if let Err(e) = exit_progress.as_ref() {
			warn!("Error progressing exits: {:#}", e);
		}
		if maintenance.is_err() || exit_sync.is_err() || exit_progress.is_err() {
			bail!("Delegated maintenance encountered errors.\nmaintenance: {:#?}\nexit_sync: {:#?}\nexit_progress: {:#?}", maintenance, exit_sync, exit_progress);
		}
		Ok(())
	}

	/// Actively join the given in-flight round `attempt` with all VTXOs due for
	/// maintenance refresh, dropping any input the server rejects as unusable and
	/// re-submitting the rest to the *same* attempt (the server keeps its submit
	/// window open after a rejection, so the corrected participation still lands
	/// in this round).
	///
	/// This is the shared core of interactive maintenance: the blocking
	/// [Wallet::maintenance_refresh] calls it and then drives the round to
	/// completion, while the daemon calls it on the round Attempt event and lets
	/// [Wallet::progress_pending_rounds] carry the round forward. Mirrors
	/// [Wallet::maybe_schedule_maintenance_refresh_delegated].
	///
	/// Returns the id of the round state we joined, or `None` if there was
	/// nothing economical to refresh.
	pub(crate) async fn join_round_for_maintenance_refresh(
		&self,
		attempt: &RoundAttempt,
	) -> anyhow::Result<Option<RoundStateId>> {
		self.maintenance_refresh_retry_loop(|part| async move {
			info!("Joining round {} for maintenance refresh ({} vtxos)",
				attempt.round_seq, part.inputs.len());
			Ok(Some(self.join_attempt_interactive(
				part, attempt, Some(RoundMovement::Refresh),
			).await?.id()))
		}).await
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
		self.maintenance_refresh_retry_loop(|part| async move {
			info!("Scheduling delegated maintenance refresh ({} vtxos)", part.inputs.len());
			Ok(Some(self.join_next_round_delegated(part, Some(RoundMovement::Refresh)).await?.id()))
		}).await
	}

	/// The retry loop shared by the interactive and delegated maintenance refreshes.
	///
	/// Selects the VTXOs due for refresh (minus any the server has already rejected
	/// as unusable), runs `attempt_refresh` for them, and if it fails naming unusable
	/// inputs, drops those and retries — up to 10 times. Both submission modes
	/// validate inputs synchronously, so a rejection surfaces here rather than
	/// poisoning the batch forever; `attempt_refresh` is the only part that differs.
	async fn maintenance_refresh_retry_loop<F, Fut>(
		&self,
		attempt_refresh: F,
	) -> anyhow::Result<Option<RoundStateId>>
	where
		F: Fn(RoundParticipation) -> Fut,
		Fut: Future<Output = anyhow::Result<Option<RoundStateId>>>,
	{
		let mut excluded = HashSet::new();
		for _ in 0..10 {
			let vtxos = self.get_vtxos_to_refresh_with_excluded(excluded.iter().copied()).await?;
			if vtxos.is_empty() {
				return Ok(None);
			}
			let part = match self.build_refresh_participation(vtxos).await? {
				Some(participation) => participation,
				None => return Ok(None),
			};

			match attempt_refresh(part).await {
				Ok(state_id) => return Ok(state_id),
				Err(e) => {
					let rejected = rejected_vtxos_from_error(&e).into_iter()
						.filter(|id| !excluded.contains(id))
						.collect::<Vec<_>>();
					if rejected.is_empty() {
						return Err(e);
					}
					warn!("Maintenance refresh rejected {} unusable input(s) ({:?}); \
						retrying without them", rejected.len(), rejected);
					excluded.extend(rejected);
				},
			}
		}
		bail!("Maintenance refresh failed after 10 retries");
	}

	/// Performs an interactive refresh of all VTXOs that are due to be refreshed, if any
	///
	/// This will include any VTXOs within the expiry threshold
	/// ([Config::vtxo_refresh_expiry_threshold]) or those which
	/// are uneconomical to exit due to onchain network conditions.
	///
	/// Waits for a round to start, joins it via [Wallet::join_round_for_maintenance_refresh]
	/// (which drops any inputs the server rejects as unusable and retries within
	/// the same attempt), then drives that round to completion.
	///
	/// Returns a [RoundStatus] if a refresh occurs.
	pub async fn maintenance_refresh(&self) -> anyhow::Result<Option<RoundStatus>> {
		if self.get_vtxos_to_refresh().await?.is_empty() {
			return Ok(None);
		}

		info!("Waiting for round to perform maintenance refresh...");
		let mut events = self.subscribe_round_events().await?;
		while let Some(event) = events.next().await {
			let event = event.context("error on round event stream")?;
			if let RoundEvent::Attempt(a) = event && a.attempt_seq == 0 {
				debug!("Round {} started, triggering maintenance refresh", a.round_seq);
				let state_id = match self.join_round_for_maintenance_refresh(&a).await? {
					Some(id) => id,
					None => return Ok(None),
				};
				// We submitted up-front, so drive the (now ongoing) round to completion
				// on this same event stream.
				let state = self.lock_wait_round_state(state_id).await?
					.context("maintenance refresh round state vanished after joining")?;
				return Ok(Some(self.drive_round_state(state, &mut events).await?));
			}
		}
		Ok(None)
	}

	/// Sync offchain wallet and update onchain fees. This is a much more lightweight alternative
	/// to [Wallet::maintenance] as it will not refresh VTXOs or sync the onchain wallet.
	///
	/// Notes:
	/// - Exits are only synced if we detect onchain activity which has force-exited our VTXO.
	pub async fn sync(&self) {
		futures::join!(
			async {
				// NB: order matters here, if syncing call fails,
				// we still want to update the fee rates
				if let Err(e) = self.inner.chain.update_fee_rates(self.inner.config.fallback_fee_rate).await {
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
				if let Err(e) = self.sync_pending_arkoor_sends().await {
					warn!("Error syncing pending arkoor sends: {:#}", e);
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
			},
			async {
				if let Err(e) = self.sync_pending_offboards().await {
					warn!("Error syncing pending offboards: {:#}", e);
				}
			},
			async {
				if let Err(e) = self.sync_force_exited_vtxos().await {
					warn!("Error scanning for on-chain-exited VTXOs: {:#}", e);
				}
			}
		);
	}

	/// Sync the transaction status of unilateral exits
	///
	/// This will not progress the unilateral exits in any way, it will merely check the
	/// transaction status of each transaction as well as check whether any exits have become
	/// claimable or have been claimed.
	pub async fn sync_exits(&self) -> anyhow::Result<()> {
		self.exit_mgr().sync(&self).await?;
		Ok(())
	}

	/// Detect spendable VTXOs that were exited on-chain without the user asking for it — e.g.
	/// the server's watchman progressing a shared tree, or a third party's unilateral exit
	/// dragging a parent on-chain — and route them into the unilateral-exit flow so the funds
	/// can be claimed on-chain.
	///
	/// Such VTXOs are otherwise left `Spendable` by a normal sync even though the server now
	/// rejects spending them, leaving the user stuck. We detect them by checking, on each new
	/// chain tip, whether any spendable VTXO's own funding tx is already on-chain.
	///
	/// This is deliberately independent of the onchain wallet sync, since the onchain wallet
	/// may be disabled. The caller must also ensure that the wallet state is up to date before
	/// calling this.
	pub async fn sync_force_exited_vtxos(&self) -> anyhow::Result<()> {
		// A VTXO's on-chain status can only change across blocks, so only scan when the tip moves.
		let tip = self.inner.chain.tip().await?;
		let mut lock = self.inner.last_force_exit_scan_tip.lock().await;
		if *lock == Some(tip) {
			return Ok(());
		}

		// Skip VTXOs already being exited.
		let exiting = self.exit_mgr().get_exit_vtxo_ids().await;
		let vtxos = self.inner.db.get_vtxos_by_state(&[VtxoStateKind::Spendable]).await?
			.into_iter()
			.filter(|v| !exiting.contains(&v.vtxo.id()));

		// Check each candidate's funding tx in parallel.
		let mut checked = FuturesUnordered::new();
		for wv in vtxos {
			let chain = self.inner.chain.clone();
			checked.push(async move {
				let txid = wv.vtxo_id().to_point().txid;
				let status = chain.tx_status(txid).await;
				(wv, status)
			});
		}

		let mut to_exit = Vec::new();
		while let Some((vtxo, status)) = futures::StreamExt::next(&mut checked).await {
			match status {
				Ok(TxStatus::NotFound) => {},
				Ok(_) => {
					info!("VTXO {} was exited on-chain without us; routing it to a claimable exit",
						vtxo.vtxo.id(),
					);
					to_exit.push(vtxo.vtxo);
				},
				Err(e) => warn!("Could not check on-chain status of VTXO {}: {:#}",
					vtxo.vtxo.id(), e,
				),
			}
		}

		if !to_exit.is_empty() {
			self.exit_mgr().start_exit_for_vtxos(&to_exit).await
				.context("failed to start exit for on-chain-exited VTXOs")?;

			*lock = Some(tip);
			self.sync_exits().await
				.context("failed to sync exits after starting new ones")?;
		} else {
			*lock = Some(tip);
		}

		Ok(())
	}

	/// Drop a specific [Vtxo] from the database. This is destructive and will result in a loss of
	/// funds.
	pub async fn dangerous_drop_vtxo(&self, vtxo_id: VtxoId) -> anyhow::Result<()> {
		warn!("Drop vtxo {} from the database", vtxo_id);
		self.inner.db.remove_vtxo(vtxo_id).await?;
		Ok(())
	}

	/// Drop all VTXOs from the database. This is destructive and will result in a loss of funds.
	//TODO(stevenroose) improve the way we expose dangerous methods
	pub async fn dangerous_drop_all_vtxos(&self) -> anyhow::Result<()> {
		warn!("Dropping all vtxos from the db...");
		for vtxo in self.vtxos().await? {
			self.inner.db.remove_vtxo(vtxo.id()).await?;
		}

		self.exit_mgr().dangerous_clear_exit().await?;
		Ok(())
	}

	/// Checks if the provided VTXO has some counterparty risk in the current wallet.
	///
	/// An arkoor vtxo is considered to have some counterparty risk if it is
	/// (directly or not) based on round VTXOs that aren't owned by the
	/// wallet. The check inspects the genesis chain, so this takes a full
	/// VTXO; callers working from a bare listing should hydrate via
	/// [Wallet::get_full_vtxo] or [BarkPersister::get_full_vtxos] first.
	async fn has_counterparty_risk(&self, vtxo: &Vtxo<Full>) -> anyhow::Result<bool> {
		for past_pks in vtxo.past_arkoor_pubkeys() {
			let mut owns_any = false;
			for past_pk in past_pks {
				if self.inner.db.get_public_key_idx(&past_pk).await?.is_some() {
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
	async fn add_should_refresh_vtxos<V: VtxoRef>(
		&self,
		participation: &mut RoundParticipation,
		exclude: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		// Get VTXOs that need and should be refreshed, then filter out any duplicates before
		// adjusting the round participation.
		let tip = self.inner.chain.tip().await?;
		let mut vtxos_to_refresh = self.spendable_vtxos_with(
			&RefreshStrategy::should_refresh(self, tip, self.inner.chain.fee_rates().await.fast),
		).await?;
		if vtxos_to_refresh.is_empty() {
			return Ok(());
		}

		let excluded_ids = participation.inputs.iter()
			.map(|v| v.vtxo_id())
			.chain(exclude.into_iter().map(|v| v.vtxo_id()))
			.collect::<HashSet<_>>();
		let mut total_amount = Amount::ZERO;
		for i in (0..vtxos_to_refresh.len()).rev() {
			let vtxo = &vtxos_to_refresh[i];
			if excluded_ids.contains(&vtxo.id()) {
				vtxos_to_refresh.swap_remove(i);
				continue;
			}
			total_amount += vtxo.amount();
		}
		if vtxos_to_refresh.is_empty() {
			// VTXOs are already included in the round participation.
			return Ok(());
		}

		// We need to verify that the output we add won't end up below the dust limit when fees are
		// applied. We can assume the base fee has been paid by the current refresh participation.
		let (_, ark_info) = self.require_server().await?;
		let fee = ark_info.fees.refresh.calculate_no_base_fee(
			vtxos_to_refresh.iter().map(|wv| VtxoFeeInfo::from_vtxo_and_tip(&wv.vtxo, tip)),
		).context("fee overflowed")?;

		// Only add these VTXOs if the output amount would be above dust after fees.
		let output_amount = match validate_and_subtract_fee_min_dust(total_amount, fee) {
			Ok(amount) => amount,
			Err(e) => {
				trace!("Cannot add should-refresh VTXOs: {}", e);
				return Ok(());
			},
		};
		info!(
			"Adding {} extra VTXOs to round participation total = {}, fee = {}, output = {}",
			vtxos_to_refresh.len(), total_amount, fee, output_amount,
		);
		let (user_keypair, _) = self.derive_store_next_keypair().await?;
		let req = VtxoRequest {
			policy: VtxoPolicy::new_pubkey(user_keypair.public_key()),
			amount: output_amount,
		};
		let extra_ids = vtxos_to_refresh.into_iter().map(|wv| wv.id()).collect::<Vec<_>>();
		let extra_full = self.inner.db.get_full_vtxos(&extra_ids).await
			.context("failed to hydrate refresh candidates")?;
		participation.inputs.reserve(extra_full.len());
		participation.inputs.extend(extra_full);
		participation.outputs.push(req);

		Ok(())
	}

	pub async fn build_refresh_participation<V: VtxoRef>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Option<RoundParticipation>> {
		let (vtxos, total_amount) = {
			let iter = vtxos.into_iter();
			let size_hint = iter.size_hint();
			let mut vtxos = Vec::<Vtxo<Full>>::with_capacity(size_hint.1.unwrap_or(size_hint.0));
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
				let vtxo = if let Some(vtxo) = vref.into_full_vtxo() {
					vtxo
				} else {
					// Listings/selection return bare wallet vtxos; the round
					// flow needs the full chain to forfeit and register.
					self.inner.db.get_full_vtxo(id).await?
						.with_context(|| format!("vtxo with id {} not found", id))?
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
		let current_height = self.inner.chain.tip().await?;
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
			unblinded_mailbox_id: None,
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

		if let Err(e) = self.add_should_refresh_vtxos(
			&mut participation, iter::empty::<VtxoId>(),
		).await {
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
	) -> anyhow::Result<Option<StoredRoundState<Unlocked>>> {
		let mut part = match self.build_refresh_participation(vtxos).await? {
			Some(participation) => participation,
			None => return Ok(None),
		};

		if let Err(e) = self.add_should_refresh_vtxos(&mut part, iter::empty::<VtxoId>()).await {
			warn!("Error trying to add additional VTXOs that should be refreshed: {:#}", e);
		}

		Ok(Some(self.join_next_round_delegated(part, Some(RoundMovement::Refresh)).await?))
	}

	/// This will find all VTXOs that meets must-refresh criteria. Then, if there are some VTXOs to
	/// refresh, it will also add those that meet should-refresh criteria.
	pub async fn get_vtxos_to_refresh(&self) -> anyhow::Result<Vec<WalletVtxo>> {
		let vtxos = self.spendable_vtxos_with(&RefreshStrategy::should_refresh_if_must(
			self,
			self.inner.chain.tip().await?,
			self.inner.chain.fee_rates().await.fast,
		)).await?;
		Ok(vtxos)
	}

	/// Similar to [Wallet::get_vtxos_to_refresh] but it allows VTXOs to be excluded from the
	/// result.
	pub async fn get_vtxos_to_refresh_with_excluded<V: VtxoRef>(
		&self,
		exclude: impl IntoIterator<Item = V>,
	) -> anyhow::Result<Vec<WalletVtxo>> {
		let mut vtxos = self.get_vtxos_to_refresh().await?;
		for v in exclude.into_iter() {
			if let Some(index) = vtxos.iter().position(|vtxo| vtxo.id() == v.vtxo_id()) {
				vtxos.swap_remove(index);
			}
		}
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
		Ok(first_expiry.map(|h| h.saturating_sub(self.inner.config.vtxo_refresh_expiry_threshold)))
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
		self.sort_vtxos_for_selection(&mut vtxos);

		let (last, _total_amount) = self.select_vtxos_inner(amount, &vtxos)?;
		vtxos.truncate(last+1);
		Ok(vtxos)
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
		let tip = self.inner.chain.tip().await?;
		let mut vtxos = self.spendable_vtxos().await?;
		self.sort_vtxos_for_selection(&mut vtxos);

		let fee_info = vtxos.iter()
			.map(|v| VtxoFeeInfo::from_vtxo_and_tip(v, tip))
			.collect::<Vec<_>>();

		// We need to loop to find suitable inputs due to the VTXOs having a direct impact on
		// how much we must pay in fees.
		const MAX_ITERATIONS: usize = 100;
		let mut fee = Amount::ZERO;
		for _ in 0..MAX_ITERATIONS {
			let required = amount.checked_add(fee)
				.context("Amount + fee overflow")?;

			let (last, vtxo_amount) = self.select_vtxos_inner(required, &vtxos)
				.context("Could not find enough suitable VTXOs to cover payment + fees")?;
			fee = calc_fee(amount, fee_info[..=last].iter().copied())?;

			if amount + fee <= vtxo_amount {
				trace!("Selected vtxos to cover amount + fee: amount = {}, fee = {}, total inputs = {}",
					amount, fee, vtxo_amount,
				);
				vtxos.truncate(last+1);
				return Ok((vtxos, fee));
			}
			trace!("VTXO sum of {} did not exceed amount {} and fee {}, iterating again",
				vtxo_amount, amount, fee,
			);
		}
		bail!("Fee calculation did not converge after maximum iterations")
	}

	/// Sorts the given `vtxos` in place ready for selection to cover funds.
	fn sort_vtxos_for_selection(&self, vtxos: &mut Vec<WalletVtxo>) {
		vtxos.sort_by_key(|v| v.expiry_height());
	}

	/// Iterates through the given `Vec` until either the given `amount` can be covered for a
	/// payment or until the `Vec` is exhausted, at which point an error will be returned.
	///
	/// Returns the index of the last VTXO included in the selection, as well as the total amount of
	/// the selected VTXOs.
	fn select_vtxos_inner(
		&self,
		amount: Amount,
		vtxos: &Vec<WalletVtxo>,
	) -> anyhow::Result<(usize, Amount)> {
		// Iterate over VTXOs until the required amount is reached
		let mut total_amount = Amount::ZERO;
		for (i, vtxo) in vtxos.iter().enumerate() {
			total_amount += vtxo.amount();

			if total_amount >= amount {
				return Ok((i, total_amount))
			}
		}

		bail!("Insufficient money available. Needed {} but {} is available",
			amount, total_amount,
		);
	}

	/// Starts a daemon for the wallet.
	///
	/// Note:
	/// - This function doesn't check if a daemon is already running,
	/// so it's possible to start multiple daemons by mistake.
	pub fn start_daemon(
		&self,
		onchain: Option<Arc<tokio::sync::RwLock<dyn DaemonizableOnchainWallet>>>,
	) -> anyhow::Result<()> {
		let mut daemon = self.inner.daemon.lock();
		if daemon.is_some() {
			warn!("Called Wallet::start_daemon while daemon was already running.");
			return Ok(());
		}

		let handle = crate::daemon::start_daemon(self.clone(), onchain);
		let _ = daemon.insert(handle);

		Ok(())
	}

	/// Use [Wallet::start_daemon] instead.
	#[deprecated(since = "0.1.4", note = "use start_daemon instead")]
	pub fn run_daemon(
		&self,
		onchain: Option<Arc<tokio::sync::RwLock<dyn DaemonizableOnchainWallet>>>,
	) -> anyhow::Result<()> {
		self.start_daemon(onchain)
	}

	/// Stops the daemon for the wallet if it is running, otherwise does nothing.
	pub fn stop_daemon(&self) {
		let mut daemon = self.inner.daemon.lock();
		if let Some(handle) = daemon.take() {
			handle.stop();
		}
	}

	/// Registers the signed transaction chains for the given VTXOs with the
	/// server. This must be called before spending VTXOs so the server can
	/// publish forfeits if needed.
	pub async fn register_vtxo_transactions_with_server(
		&self,
		vtxos: &[impl AsRef<Vtxo<Full>>],
	) -> anyhow::Result<()> {
		if vtxos.is_empty() {
			return Ok(());
		}

		let (mut srv, _) = self.require_server().await?;
		srv.client.register_vtxo_transactions(protos::RegisterVtxoTransactionsRequest {
			vtxos: vtxos.iter().map(|v| v.as_ref().serialize()).collect(),
		}).await.context("failed to register vtxo transactions")?;

		Ok(())
	}
}

fn wrap_server_connect_error(err: ConnectError) -> anyhow::Error {
	match err {
		ConnectError::CreateEndpoint(CreateEndpointError::NoTransportBackend) => {
			anyhow!(MISSING_SERVER_TRANSPORT_HELP)
		},
		other => anyhow::Error::from(other),
	}
}

impl std::ops::Drop for WalletInner {
	fn drop(&mut self) {
		if let Some(handle) = self.daemon.lock().take() {
			handle.stop();
		}
	}
}

#[cfg(test)]
mod tests {
	use server_rpc::client::CreateEndpointError;

	use super::{wrap_server_connect_error, MISSING_SERVER_TRANSPORT_HELP};

	#[test]
	fn no_transport_connect_error_is_reworded_for_wallet_users() {
		let err = wrap_server_connect_error(CreateEndpointError::NoTransportBackend.into());
		assert!(err.to_string().contains(MISSING_SERVER_TRANSPORT_HELP));
		assert!(err.to_string().contains("feature `bark-wallet/native` or `bark-wallet/wasm-web`"));
	}
}
