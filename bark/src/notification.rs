use std::pin::Pin;

use futures::stream::{Stream, unfold};
use tokio::sync::broadcast;

use crate::Wallet;

/// A notification emitted by the wallet.
///
/// Notification content will be defined later.
#[derive(Debug, Clone)]
pub enum WalletNotification {}

/// Handle for subscribing to wallet notifications.
pub struct NotificationHandle {
	tx: broadcast::Sender<WalletNotification>,
}

impl NotificationHandle {
	pub(crate) fn new() -> Self {
		let (tx, _rx) = broadcast::channel(64);
		NotificationHandle { tx }
	}

	pub(crate) fn subscribe(&self) -> Pin<Box<dyn Stream<Item = WalletNotification> + Send>> {
		let rx = self.tx.subscribe();
		Box::pin(unfold(rx, |mut rx| async move {
			loop {
				match rx.recv().await {
					Ok(item) => return Some((item, rx)),
					Err(broadcast::error::RecvError::Lagged(_)) => continue,
					Err(broadcast::error::RecvError::Closed) => return None,
				}
			}
		}))
	}

	/// Send a notification to all subscribers.
	pub(crate) fn send(&self, notification: WalletNotification) {
		let _ = self.tx.send(notification);
	}
}

impl Wallet {
	/// Subscribe to a stream of wallet notifications.
	///
	/// Returns a [`Stream`] that yields [`WalletNotification`] items as they are
	/// emitted by the wallet. Multiple subscribers can be active at the same
	/// time; each receives its own independent copy of every notification.
	///
	/// # Example
	///
	/// ```no_run
	/// use futures::StreamExt;
	///
	/// # async fn demo(wallet: &bark::Wallet) {
	/// let mut notifications = wallet.subscribe_notifications();
	/// while let Some(event) = notifications.next().await {
	///     // handle event
	/// }
	/// # }
	/// ```
	pub fn subscribe_notifications(&self) -> impl Stream<Item = WalletNotification> + Unpin + Send {
		self.notifications.subscribe()
	}
}
