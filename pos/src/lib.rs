//! posd, the scuttle point-of-sale service.
//!
//! posd pairs terminals to a store, creates sales and watches three payment
//! rails. Every rail pays the store owner's wallet directly: posd never
//! holds the funds and terminals cannot send.
//!
//! - Lightning: a forwarding invoice from a private barkd.
//! - Ark: a hinted invoice from the Ark server, certified by its delivery
//!   receipt.
//! - On-chain: an address from the owner's public descriptor.

pub mod api;
pub mod config;
pub mod database;
pub mod error;
pub mod money;
pub mod price;
pub mod rails;
pub mod registration;
pub mod sales;
pub mod token;
pub mod watcher;

use std::sync::Arc;

use anyhow::Context;
use tokio::sync::watch;

use crate::config::Config;
use crate::database::Db;
use crate::price::PriceFeed;
use crate::rails::forward::Forwarder;
use crate::rails::hinted::ArkServer;
use crate::rails::onchain::Chain;


pub struct App {
	pub cfg: Config,
	pub db: Db,
	pub price: PriceFeed,
	pub forwarder: Forwarder,
	pub ark: ArkServer,
	pub chain: Chain,
	/// Bumped whenever a sale changes state, to wake long-polls.
	pub sale_changes: watch::Sender<u64>,
}

impl App {
	pub async fn new(cfg: Config) -> anyhow::Result<Arc<App>> {
		let db = Db::connect(&cfg.postgres).await?;
		let ark = ArkServer::connect(&cfg).await?;
		let info = ark.ark_info().await;
		if info.network != cfg.network {
			anyhow::bail!("the Ark server runs on {}, not {}", info.network, cfg.network);
		}
		let app = App {
			price: PriceFeed::new(cfg.price.clone())?,
			forwarder: Forwarder::new(&cfg.barkd)?,
			chain: Chain::connect(&cfg).await.context("failed to set up the chain source")?,
			sale_changes: watch::channel(0).0,
			db,
			ark,
			cfg,
		};
		Ok(Arc::new(app))
	}

	pub fn notify_sale_change(&self) {
		self.sale_changes.send_modify(|v| *v = v.wrapping_add(1));
	}
}
