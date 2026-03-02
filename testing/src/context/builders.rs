use std::sync::Arc;
use std::time::Duration;

use bark::BarkNetwork;
use bitcoin::Amount;

use crate::{Bark, Bitcoind, Captaind, Lightningd, LightningdConfig};
use crate::util::FutureExt;
use super::TestContext;

// ── CaptaindBuilder ─────────────────────────────────────────────────

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

	pub async fn create(self) -> Captaind {
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

		let mut ret = Captaind::new(&self.name, bitcoind, cfg);
		ret.start().await.unwrap();

		if let Some(amount) = self.fund_amount {
			self.ctx.fund_captaind(&ret, amount).await;
		}

		ret
	}
}

// ── BarkBuilder ─────────────────────────────────────────────────────

pub struct BarkBuilder<'a> {
	ctx: &'a TestContext,
	name: String,
	srv: &'a dyn super::ToArkUrl,
	own_bitcoind: bool,
	fund_amount: Option<Amount>,
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

		if let Some(mod_cfg) = self.mod_cfg {
			mod_cfg(&mut cfg);
		}

		let datadir = self.ctx.datadir.join(&self.name);
		let bark = Bark::try_new(&self.name, datadir, BarkNetwork::Regtest, cfg, bitcoind).await?;

		if let Some(amount) = self.fund_amount {
			self.ctx.fund_bark(&bark, amount).await;
		}

		Ok(bark)
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

		let cfg = LightningdConfig {
			network: String::from("regtest"),
			bitcoin_dir: bitcoind.datadir(),
			bitcoin_rpcport: bitcoind.rpc_port(),
			lightning_dir: self.ctx.datadir.join(&self.name),
		};

		let mut ret = Lightningd::new(&self.name, bitcoind, cfg);
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
