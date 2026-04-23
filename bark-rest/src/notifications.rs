use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;
use std::time::Duration;

use bark::{Wallet, WalletNotification};
use chrono::{DateTime, Utc};
use futures::StreamExt;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// The time to keep notifications in the buffer before purging them
const NOTIFICATION_BUFFER_TTL_SECONDS: u64 = 600;

#[derive(Clone)]
struct NotificationBuffer {
	inner: Arc<RwLock<BTreeMap<DateTime<Utc>, Vec<WalletNotification>>>>,
	notify: Arc<tokio::sync::Notify>,
}

impl NotificationBuffer {
	fn new() -> Self {
		Self { inner: Arc::new(RwLock::new(BTreeMap::new())), notify: Arc::new(tokio::sync::Notify::new()) }
	}

	async fn push(&self, timestamp: DateTime<Utc>, notification: WalletNotification) {
		let mut lock = self.inner.write().await;
		lock.entry(timestamp).or_insert_with(Vec::new).push(notification);
		self.notify.notify_waiters();
	}

	/// Purge notifications older than the given timestamp
	 async fn purge(&self, timestamp: DateTime<Utc>) {
		let mut lock = self.inner.write().await;
		lock.retain(|t, _| *t > timestamp);
	}

	async fn get_since(&self, since: Option<DateTime<Utc>>)
		-> Option<(DateTime<Utc>, Vec<WalletNotification>)>
	{
		let lock = self.inner.read().await;
		let notifications = match since {
			Some(since) => lock.range((Excluded(since), Unbounded)),
			None => lock.range(..),
		};

		let last_pushed_at = notifications.clone().last()
			.map(|(timestamp, _)| *timestamp);

		// Get all fresh notifications
		let notifications = notifications
			.flat_map(|(_, notifications)| notifications)
			.cloned()
			.collect::<Vec<_>>();

		if let Some(last_pushed_at) = last_pushed_at {
			return Some((last_pushed_at, notifications));
		}

		None
	}
}

/// A process that runs in the background and reads notifications from the buffer
struct NotificationManagerProcess {
	wallet: Wallet,
	shutdown: CancellationToken,
}

impl NotificationManagerProcess {
	pub(crate) fn run(self, buffer: NotificationBuffer) -> tokio::task::JoinHandle<()> {
		let mut stream = self.wallet.subscribe_notifications();

		tokio::spawn(async move {
			loop {
				tokio::select! {
					notification = stream.next() => {
						if let Some(notification) = notification {
							let now = Utc::now();

							let expiration_bound = now - Duration::from_secs(NOTIFICATION_BUFFER_TTL_SECONDS);
							buffer.purge(expiration_bound).await;

							buffer.push(now, notification.clone()).await;
						}
					}
					_ = self.shutdown.cancelled() => {
						log::info!("Shutdown signal received! Shutting down notification manager...");
						break;
					}
				}
			}
		})
	}
}

struct NotificationManagerInner {
	buffer: NotificationBuffer,
	shutdown: CancellationToken,
	_jh: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
pub struct NotificationManager(Arc<NotificationManagerInner>);

impl NotificationManager {
	pub(crate) fn start(wallet: Wallet, shutdown: CancellationToken) -> Self {
		let buffer = NotificationBuffer::new();

		let process = NotificationManagerProcess { wallet, shutdown: shutdown.clone() };
		let jh = process.run(buffer.clone());

		Self(Arc::new(NotificationManagerInner {
			buffer,
			shutdown: shutdown.clone(),
			_jh: jh,
		}))
	}

	pub(crate) async fn wait_notifications(&self, since: Option<DateTime<Utc>>) -> Option<(DateTime<Utc>, Vec<WalletNotification>)> {
		if let Some(notifications) = self.0.buffer.get_since(since).await {
			return Some(notifications);
		}

		loop {
			tokio::select! {
				_ = self.0.buffer.notify.notified() => {
					if let Some(notifications) = self.0.buffer.get_since(since).await {
						return Some(notifications);
					}
				}
				_ = self.0.shutdown.cancelled() => {
					return None;
				}
			}
		}
	}
}