use std::time::Duration;
use std::sync::Arc;

use anyhow::Context;
use parking_lot;
use log::{info, warn};

use bitcoin_ext::BlockRef;
use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};

use crate::system::RuntimeManager;
use crate::telemetry;

pub struct TipFetcher {
	tip: Arc<parking_lot::Mutex<BlockRef>>
}


impl TipFetcher {

	pub fn tip(&self) -> BlockRef {
		self.tip.lock().clone()
	}

	pub async fn start(
		rtmgr: RuntimeManager,
		bitcoin: BitcoinRpcClient,
	) -> anyhow::Result<Self> {
		let tip = bitcoin.tip()
			.context("Failed to retrieve tip from bitcoind")?;

		let fetcher = TipFetcher { tip: Arc::new(parking_lot::Mutex::new(tip)) };

		let proc = Process {
			tip: fetcher.tip.clone(),
			bitcoin: bitcoin.clone(),
		};

		tokio::spawn(proc.run(rtmgr));
		Ok(fetcher)
	}
}

#[derive(Clone)]
struct Process {
	tip: Arc<parking_lot::Mutex<BlockRef>>,
	bitcoin: BitcoinRpcClient,
}


impl Process {

	pub async fn update(&self) {
		match self.bitcoin.tip() {
			Ok(tip) => {
				let mut lock = self.tip.lock();
				if tip!= *lock {
					*lock = tip;
					telemetry::set_block_height(tip.height);
					slog!(TipUpdated, height: tip.height, hash: tip.hash);
				}
			}
			Err(e) => {
				warn!("Error getting chain tip from bitcoind: {}", e);
			}
		}
	}

	async fn run(self, rtmgr: RuntimeManager)  {
		let _worker = rtmgr.spawn_critical("TipFetcher");

		loop {
			tokio::select!{
				() = tokio::time::sleep(Duration::from_secs(1)) => {},
				_ = rtmgr.shutdown_signal() => {
					info!("Shutdown signal received. Exiting TipFetcher loop...");
					break;
				}
			}

			self.update().await
		}

		info!("TipFetcher loop terminated gracefully.");
	}
}
