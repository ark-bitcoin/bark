//! Listen for tip updates via ZMQ.

use std::sync::Arc;
use std::time::Duration;

use futures::FutureExt;
use log::{error, info, warn};
use tokio::sync::watch;
use zeromq::{Socket, SocketRecv};

use bark_runtime::CancellationToken;
use bitcoin_ext::BlockRef;

use super::source::TipSource;

/// The ZMQ topic that announces the hash of every new block.
const HASHBLOCK_TOPIC: &str = "hashblock";

pub(super) struct ZmqTipWatcher<S: TipSource> {
	pub source: Arc<S>,
	pub reconcile_interval: Duration,
	pub shutdown: CancellationToken,
	pub tx: watch::Sender<BlockRef>,
	pub socket: zeromq::SubSocket,
}

impl<S: TipSource> ZmqTipWatcher<S> {
	pub async fn run(self) {
		let Self {
			source,
			reconcile_interval,
			shutdown,
			tx,
			mut socket,
		} = self;

		loop {
			futures::select! {
				res = socket.recv().fuse() => {
					if let Err(e) = res {
						error!("ZMQ receive failed: {e:#}");
						break;
					}
				},
				// The reconcile deadline restarts on every pass. A
				// notification refreshes the tip from the source just like
				// a reconcile does, so the timer only has to cover
				// stretches without notifications.
				_ = bark_runtime::sleep(reconcile_interval).fuse() => {},
				_ = shutdown.cancelled().fuse() => break,
			}

			// A notification or the reconcile timer woke us; the
			// notification only carries the block hash, so the new
			// tip always comes from the source.
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

/// Connect to the ZMQ endpoint and subscribe to block notifications.
pub(super) async fn connect(endpoint: &str) -> anyhow::Result<zeromq::SubSocket> {
	let mut socket = zeromq::SubSocket::new();
	socket.connect(endpoint).await
		.map_err(|e| anyhow::anyhow!("failed to connect to ZMQ endpoint {}: {e:#}", endpoint))?;
	socket.subscribe(HASHBLOCK_TOPIC).await
		.map_err(|e| anyhow::anyhow!("failed to subscribe to '{}': {e:#}", HASHBLOCK_TOPIC))?;

	info!("connected to ZMQ endpoint: {}", endpoint);
	Ok(socket)
}
