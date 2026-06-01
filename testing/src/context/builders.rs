use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bark::{BarkNetwork, OpenWalletArgs, WalletSeed};
use bark::onchain::{OnchainWallet, OnchainWalletTrait};
use bark::persist::BarkPersister;
use bark::persist::sqlite::SqliteClient;
use bitcoin::Amount;
use server::wallet::MNEMONIC_FILE;
use tokio::fs;

use crate::constants::BOARD_CONFIRMATIONS;
use crate::daemon::barkd::{Barkd, BarkdChainSource};
use crate::daemon::watchmand::Watchmand;
use crate::{Bark, Bitcoind, Captaind, Lightningd, LightningdConfig};
use crate::util::FutureExt;
use super::TestContext;

// If the caller asked us to board but didn't specify how much
// onchain to send, cover all board amounts plus a generous fee
// buffer.
const BOARD_ONCHAIN_FEE_BUFFER: Amount = Amount::from_sat(100_000);

pub struct CaptaindBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	bitcoind: Option<Arc<Bitcoind>>,
	fund_amount: Option<Amount>,
	lightningd: Option<&'a Lightningd>,
	mod_cfg: Option<Box<dyn FnOnce(&mut server::Config)>>,
}

impl<'a> CaptaindBuilder<'a> {
	pub(super) fn new(ctx: &'a TestContext, name: impl AsRef<str>) -> Self {
		CaptaindBuilder {
			ctx,
			name: name.as_ref().to_string(),
			bitcoind: None,
			fund_amount: None,
			lightningd: None,
			mod_cfg: None,
		}
	}

	pub fn bitcoind(mut self, bitcoind: Arc<Bitcoind>) -> Self {
		self.bitcoind = Some(bitcoind);
		self
	}

	pub fn funded(mut self, amount: Amount) -> Self {
		self.fund_amount = Some(amount);
		self
	}

	pub fn lightningd(mut self, ln: &'a Lightningd) -> Self {
		self.lightningd = Some(ln);
		self
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut server::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	/// Create the server but do not register it as the main server for the test
	pub async fn create_unregistered(self) -> Captaind {
		let bitcoind = match self.bitcoind {
			Some(bitcoind) => bitcoind,
			None => Arc::new(self.ctx.new_bitcoind(format!("{}_bitcoind", self.name)).await),
		};

		let mut cfg = self.ctx.captaind_default_cfg(
			&self.name, &bitcoind, self.lightningd,
		).await;
		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		let ret = Captaind::new(&self.name, bitcoind, cfg);
		ret.start().await.unwrap();

		if let Some(amount) = self.fund_amount {
			self.ctx.fund_captaind(&ret, amount).await;
		}

		ret
	}

	/// Create the server and register it as the main server for the test
	pub async fn create(self) -> Arc<Captaind> {
		let ctx = self.ctx;
		let ret = Arc::new(self.create_unregistered().await);
		ctx.register_test_captaind(ret.clone());
		ret
	}
}

pub struct WatchmandBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	bitcoind: Option<Arc<Bitcoind>>,
	mod_cfg: Option<Box<dyn FnOnce(&mut server::config::watchmand::Config)>>,
}

impl<'a> WatchmandBuilder<'a> {
	pub(super) fn new(ctx: &'a TestContext, name: impl AsRef<str>) -> Self {
		WatchmandBuilder {
			ctx,
			name: name.as_ref().to_string(),
			bitcoind: None,
			mod_cfg: None,
		}
	}

	pub fn bitcoind(mut self, bitcoind: Arc<Bitcoind>) -> Self {
		self.bitcoind = Some(bitcoind);
		self
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut server::config::watchmand::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	pub async fn create(self, srv: &Captaind) -> Watchmand {
		let bitcoind = match self.bitcoind {
			Some(bitcoind) => bitcoind,
			None => Arc::new(self.ctx.new_bitcoind(format!("{}_bitcoind", self.name)).await),
		};

		let mut cfg = self.ctx.watchmand_default_cfg(
			&self.name, &bitcoind, srv,
		).await;
		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		// we need to create the datadir and copy the server mnemonic
		fs::create_dir_all(&cfg.data_dir).await.expect("failed to create watchmand datadir");
		fs::copy(
			srv.config().data_dir.join(MNEMONIC_FILE),
			cfg.data_dir.join(MNEMONIC_FILE),
		).await.expect("failed to copy mnemonic file for watchmand");

		let ret = Watchmand::new(&self.name, bitcoind, cfg);
		ret.start().await.unwrap();

		ret
	}
}

// ── BarkdBuilder ────────────────────────────────────────────────────

pub struct BarkdBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	srv: &'a Captaind,
	mod_cfg: Option<Box<dyn FnOnce(&mut bark::Config)>>,
	fund_amount: Option<Amount>,
	board_amount: Option<Amount>,
	env: std::collections::HashMap<String, String>,
}

impl<'a> BarkdBuilder<'a> {
	pub(super) fn new(
		ctx: &'a TestContext,
		name: impl AsRef<str>,
		srv: &'a Captaind,
	) -> Self {
		BarkdBuilder {
			ctx,
			name: name.as_ref().to_string(),
			srv,
			mod_cfg: None,
			fund_amount: None,
			board_amount: None,
			env: std::collections::HashMap::new(),
		}
	}

	/// Set an extra environment variable on the spawned barkd process.
	pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
		self.env.insert(key.into(), value.into());
		self
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut bark::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	/// Fund the daemon's onchain wallet with `amount` after the wallet has
	/// been created.
	pub fn funded(mut self, amount: Amount) -> Self {
		self.fund_amount = Some(amount);
		self
	}

	/// Provide `amount` of on-chain coins to the daemon's wallet and then
	/// board it all into Ark. Returns once the board tx is confirmed and
	/// the resulting VTXO has been registered with the Ark server.
	pub fn boarded(mut self, amount: Amount) -> Self {
		self.board_amount = Some(amount);
		self
	}

	pub async fn create(self) -> Barkd {
		let (chain_source, bitcoind) = if let Some(electrs) = &self.ctx.electrs {
			(BarkdChainSource::Esplora(electrs.rest_url()), None)
		} else {
			let bd = self.ctx.new_bitcoind(format!("{}_bitcoind", self.name)).await;
			let chain_source = BarkdChainSource::Bitcoind {
				url: bd.rpc_url(),
				cookie: bd.rpc_cookie(),
			};
			(chain_source, Some(bd))
		};

		let datadir = self.ctx.datadir.join(&self.name);

		let mut cfg = self.ctx.bark_default_cfg(self.srv, bitcoind.as_ref().map(|b| b as &Bitcoind));
		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}
		std::fs::create_dir_all(&datadir).unwrap();
		let config_toml = toml::to_string(&cfg).unwrap();
		std::fs::write(datadir.join("config.toml"), config_toml).unwrap();

		let daemon = Barkd::new(
			&self.name, datadir, self.srv.ark_url(), chain_source, bitcoind,
		);
		for (k, v) in self.env {
			daemon.set_env(k, v);
		}
		daemon.start().await.expect("failed to start barkd");
		daemon.create_wallet().await.expect("failed to create barkd wallet");

		if let Some(amount) = self.board_amount {
			self.ctx.fund_barkd(&daemon, amount).await;
			// Force an onchain sync so the funding tx is visible before
			// board_all tries to spend it.
			daemon.onchain_sync().await;
			let b = daemon.board_all().await;
			self.ctx.await_transaction(b.funding_tx.txid).await;
			self.ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
			daemon.sync().await;
		}

		if let Some(amount) = self.fund_amount {
			self.ctx.fund_barkd(&daemon, amount).await;
		}

		daemon
	}
}

// ── BarkBuilder ─────────────────────────────────────────────────────

pub struct BarkBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	srv: &'a dyn super::ToArkUrl,
	own_bitcoind: bool,
	fund_amount: Option<Amount>,
	board_amounts: Vec<Amount>,
	server_address: Option<String>,
	chain_address: Option<String>,
	socks5_proxy: Option<String>,
	mod_cfg: Option<Box<dyn FnOnce(&mut bark::Config)>>,
}

impl<'a> BarkBuilder<'a> {
	pub(super) fn new(ctx: &'a TestContext, name: impl AsRef<str>, srv: &'a dyn super::ToArkUrl) -> Self {
		BarkBuilder {
			ctx,
			name: name.as_ref().to_string(),
			srv,
			own_bitcoind: false,
			fund_amount: None,
			board_amounts: Vec::new(),
			server_address: None,
			chain_address: None,
			socks5_proxy: None,
			mod_cfg: None,
		}
	}

	pub fn own_bitcoind(mut self) -> Self {
		self.own_bitcoind = true;
		self
	}

	pub fn funded(mut self, amount: Amount) -> Self {
		self.fund_amount = Some(amount);
		self
	}

	pub fn boarded(mut self, amount: Amount) -> Self {
		self.board_amounts.push(amount);
		self
	}

	/// Override the Ark server address (e.g. with a .onion address).
	pub fn server_address(mut self, addr: impl Into<String>) -> Self {
		self.server_address = Some(addr.into());
		self
	}

	/// Override the chain source address (esplora or bitcoind, whichever
	/// the test context uses) with e.g. a .onion address.
	pub fn chain_address(mut self, addr: impl Into<String>) -> Self {
		self.chain_address = Some(addr.into());
		self
	}

	/// Route non-local traffic through a SOCKS5 proxy.
	pub fn socks5_proxy(mut self, proxy: impl Into<String>) -> Self {
		self.socks5_proxy = Some(proxy.into());
		self
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut bark::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	pub async fn create(self) -> Bark {
		self.try_create().await.unwrap()
	}

	pub async fn try_create(self) -> anyhow::Result<Bark> {
		let bitcoind = if self.ctx.electrs.is_some() {
			None
		} else if self.own_bitcoind {
			Some(Arc::new(self.ctx.new_bitcoind(format!("{}_bitcoind", self.name)).await))
		} else {
			Some(self.ctx.bitcoind_arc())
		};

		let mut cfg = self.ctx.bark_default_cfg(self.srv, bitcoind.as_deref());

		if let Some(addr) = self.server_address {
			cfg.server_address = addr;
		}
		if let Some(addr) = self.chain_address {
			if cfg.esplora_address.is_some() {
				cfg.esplora_address = Some(addr);
			} else {
				cfg.bitcoind_address = Some(addr);
			}
		}
		cfg.socks5_proxy = self.socks5_proxy;

		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		let datadir = self.ctx.datadir.join(&self.name);
		let bark = Bark::try_new(&self.name, datadir, BarkNetwork::Regtest, cfg, bitcoind).await?;

		let fund_amount = self.fund_amount.or_else(|| {
			if self.board_amounts.is_empty() {
				None
			} else {
				Some(self.board_amounts.iter().copied().sum::<Amount>() + BOARD_ONCHAIN_FEE_BUFFER)
			}
		});
		if let Some(amount) = fund_amount {
			self.ctx.fund_bark(&bark, amount).await;
		}
		if !self.board_amounts.is_empty() {
			for amount in &self.board_amounts {
				let b = bark.try_board(*amount).await.context("board_amount")?;
				self.ctx.await_transaction(b.funding_tx.txid).await;
			}
			self.ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
			bark.sync().await;
		}

		Ok(bark)
	}
}

// ── BarkSdkBuilder ──────────────────────────────────────────────────

/// Builds an in-process [`bark::Wallet`] for `bark-sdk` integration tests.
///
/// Mirrors [`BarkBuilder`], but instead of spawning the `bark` CLI binary
/// it constructs a [`bark::Wallet`] directly via the library API and
/// returns it ready to use.
pub struct BarkSdkBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	srv: &'a dyn super::ToArkUrl,
	fund_amount: Option<Amount>,
	board_amounts: Vec<Amount>,
	mod_cfg: Option<Box<dyn FnOnce(&mut bark::Config)>>,
}

impl<'a> BarkSdkBuilder<'a> {
	pub(super) fn new(
		ctx: &'a TestContext,
		name: impl AsRef<str>,
		srv: &'a dyn super::ToArkUrl,
	) -> Self {
		BarkSdkBuilder {
			ctx,
			name: name.as_ref().to_string(),
			srv,
			fund_amount: None,
			board_amounts: Vec::new(),
			mod_cfg: None,
		}
	}

	pub fn cfg(mut self, f: impl FnOnce(&mut bark::Config) + 'static) -> Self {
		self.mod_cfg = Some(Box::new(f));
		self
	}

	/// Send `amount` to a fresh onchain address of the wallet before
	/// returning it. If unset and [`Self::boarded`] is set, enough
	/// onchain funds are sent automatically to cover all boards plus
	/// fees.
	pub fn funded(mut self, amount: Amount) -> Self {
		self.fund_amount = Some(amount);
		self
	}

	/// Board `amount` from the onchain wallet into Ark, wait for the
	/// configured number of board confirmations, and sync the wallet so
	/// the resulting VTXO is registered with the Ark server.
	///
	/// May be called multiple times to produce multiple distinct VTXOs;
	/// each call appends a separate board.
	pub fn boarded(mut self, amount: Amount) -> Self {
		self.board_amounts.push(amount);
		self
	}

	pub async fn create(self) -> bark::Wallet {
		self.try_create().await.unwrap()
	}

	pub async fn try_create(self) -> anyhow::Result<bark::Wallet> {
		let bitcoind = if self.ctx.electrs.is_some() {
			None
		} else {
			Some(self.ctx.bitcoind_arc())
		};

		let mut cfg = self.ctx.bark_default_cfg(self.srv, bitcoind.as_deref());
		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		let datadir = self.ctx.datadir.join(&self.name);
		fs::create_dir_all(&datadir).await
			.with_context(|| format!("creating bark-sdk datadir at {}", datadir.display()))?;

		let network = BarkNetwork::Regtest.as_bitcoin();
		let mnemonic = bip39::Mnemonic::generate(12).context("mnemonic")?;
		fs::write(datadir.join("mnemonic"), mnemonic.to_string()).await
			.context("writing mnemonic file")?;
		fs::write(
			datadir.join("config.toml"),
			toml::to_string_pretty(&cfg).unwrap(),
		).await.context("writing config.toml")?;

		let db: Arc<dyn BarkPersister> = Arc::new(
			SqliteClient::open(datadir.join("db.sqlite")).context("opening sqlite db")?,
		);

		let mut onchain = OnchainWallet::load_or_create(
			network, mnemonic.to_seed(""), db.clone(),
		).await.context("creating onchain wallet")?;

		let seed = WalletSeed::new_from_mnemonic(network, &mnemonic);
		let wallet = bark::Wallet::open(network, seed, cfg, OpenWalletArgs {
			persister: Some(db),
			create_if_not_exists: true,
			..Default::default()
		}).await.context("creating bark wallet")?;

		let fund_amount = self.fund_amount.or_else(|| {
			if self.board_amounts.is_empty() {
				None
			} else {
				Some(self.board_amounts.iter().copied().sum::<Amount>() + BOARD_ONCHAIN_FEE_BUFFER)
			}
		});
		if let Some(amount) = fund_amount {
			let address = onchain.address().await.context("onchain address")?;
			self.ctx.bitcoind().fund_addr(address, amount).await;
			self.ctx.bitcoind().generate(1).await;
			self.ctx.await_block_count_sync().await;
			onchain.sync(wallet.chain()).await.context("onchain sync after funding")?;
		}

		if !self.board_amounts.is_empty() {
			for amount in &self.board_amounts {
				let b = wallet.board_amount(*amount).await.context("board_amount")?;
				self.ctx.await_transaction(b.funding_tx.compute_txid()).await;
			}
			self.ctx.generate_blocks(BOARD_CONFIRMATIONS).await;
			wallet.sync().await;
		}

		Ok(wallet)
	}
}

// ── LightningdBuilder ───────────────────────────────────────────────

pub struct LightningdBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	own_bitcoind: bool,
}

impl<'a> LightningdBuilder<'a> {
	pub(super) fn new(ctx: &'a TestContext, name: impl AsRef<str>) -> Self {
		LightningdBuilder {
			ctx,
			name: name.as_ref().to_string(),
			own_bitcoind: false,
		}
	}

	pub fn own_bitcoind(mut self) -> Self {
		self.own_bitcoind = true;
		self
	}

	pub async fn create(self) -> Lightningd {
		let bitcoind = if self.own_bitcoind {
			Arc::new(self.ctx.new_bitcoind(format!("{}_bitcoind", self.name)).await)
		} else {
			self.ctx.bitcoind_arc()
		};

		// Generate a block with a fresh timestamp so bitcoind exits
		// initialblockdownload mode. Without this, CLN reports
		// "Bitcoind is not up-to-date with network." indefinitely
		// when started from a stale snapshot.
		bitcoind.generate(1).await;

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: self.ctx.datadir.join(&self.name),
		};

		let ret = Lightningd::new(&self.name, bitcoind, cfg);
		ret.start().await.unwrap();

		// wait for grpc to be available
		async {
			loop {
				if ret.try_grpc_client().await.is_ok() {
					break;
				} else {
					tokio::time::sleep(Duration::from_millis(200)).await;
				}
			}
		}.wait_millis(5000).await;

		ret
	}
}
