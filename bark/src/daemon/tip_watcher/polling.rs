//! Poll the tip at intervals.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use log::warn;
use tokio::sync::watch;

use bark_runtime::CancellationToken;
use bitcoin_ext::BlockRef;

use super::source::TipSource;

pub(super) struct PollingTipWatcher<S: TipSource> {
	pub source: Arc<S>,
	pub poll_interval: Duration,
	pub shutdown: CancellationToken,
	pub tx: watch::Sender<BlockRef>,
}

impl<S: TipSource> PollingTipWatcher<S> {
	pub async fn run(self) {
		let Self {
			source,
			poll_interval,
			shutdown,
			tx,
		} = self;
		loop {
			futures::select! {
				_ = bark_runtime::sleep(poll_interval).fuse() => {},
				_ = shutdown.cancelled().fuse() => break,
			}
			match source.tip_ref().await {
				Ok(tip) => {
					tx.send_if_modified(|current| {
						if *current != tip {
							*current = tip;
							true
						} else {
							false
						}
					});
				}
				Err(e) => {
					warn!("tip watcher failed to fetch tip: {e:#}");
				}
			}
		}
	}
}
