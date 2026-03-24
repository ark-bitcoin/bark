use std::pin::Pin;
use std::task::Poll;

use futures::stream::Stream;
use futures::TryStreamExt;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use ark::lightning::AsPaymentHash;

use crate::Wallet;
use crate::movement::{Movement, PaymentMethod};
use crate::subsystem::{LightningMovement, Subsystem};

/// A notification emitted by the wallet.
#[derive(Debug, Clone)]
pub enum WalletNotification {
	/// A new movement was created
	MovementCreated {
		movement: Movement,
	},
	/// An existing movement was updated
	MovementUpdated {
		movement: Movement,
	},
}

/// A stream that yields all wallet notifications
///
/// The stream has various utility methods to convert and filter the stream.
///
/// If the stream's buffer is full and notifications are not handled fast enough,
/// they will be silently dropped.
pub struct NotificationStream {
	rx: BroadcastStream<WalletNotification>,
}

impl NotificationStream {
	pub(crate) fn new(rx: broadcast::Receiver<WalletNotification>) -> Self {
		Self {
			rx: BroadcastStream::new(rx),
		}
	}

	/// Convert into a stream that simply yields movements whenever an update happens
	pub fn movements(self) -> impl Stream<Item = Movement> + Unpin + Send {
		self.filter_map(|n| match n {
			WalletNotification::MovementCreated { movement } => Some(movement),
			WalletNotification::MovementUpdated { movement } => Some(movement),
		})
	}

	/// Filter only movements for the given arkoor address
	pub fn filter_arkoor_address_movements(
		self,
		address: ark::Address,
	) -> impl Stream<Item = Movement> + Unpin + Send {
		self.movements().filter(move |m| {
			if !m.subsystem.is_subsystem(Subsystem::ARKOOR) {
				return false;
			}

			m.received_on.iter().any(|d| match d.destination {
				PaymentMethod::Ark(ref a) if *a == address => true,
				_ => false,
			})
		})
	}

	/// Filter only movements for the given Lightning payment hash
	///
	/// You can pass any invoice type or a [PaymentHash] as a filter.
	pub fn filter_lightning_payment_movements(
		self,
		payment: impl AsPaymentHash,
	) -> impl Stream<Item = Movement> + Unpin + Send {
		let payment_hash = payment.as_payment_hash();
		self.movements().filter(move |m| {
			if !m.subsystem.is_subsystem(Subsystem::LIGHTNING_RECEIVE)
				&& !m.subsystem.is_subsystem(Subsystem::LIGHTNING_SEND)
			{
				return false;
			}

			if LightningMovement::get_payment_hash(&m.metadata) == Some(payment_hash) {
				return true;
			}

			for d in &m.received_on {
				match d.destination {
					PaymentMethod::Invoice(ref i) if i.payment_hash() == payment_hash => {
						return true;
					},
					_ => {},
				}
			}

			false
		})
	}

	/// Convert into the raw [BroadcastStream]
	///
	/// The raw stream gives slightly more control. For example it lets you know if
	/// you are lagging behind on items.
	pub fn into_raw_stream(self) -> BroadcastStream<WalletNotification> {
		self.rx
	}
}

impl Stream for NotificationStream {
	type Item = WalletNotification;
	fn poll_next(
		mut self: Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> Poll<Option<Self::Item>> {
		match self.rx.try_poll_next_unpin(cx) {
			Poll::Pending => Poll::Pending,
			Poll::Ready(None) | Poll::Ready(Some(Err(_))) => Poll::Ready(None),
			Poll::Ready(Some(Ok(m))) => Poll::Ready(Some(m)),
		}
	}
}

#[derive(Clone)]
pub(crate) struct NotificationDispatch {
	tx: broadcast::Sender<WalletNotification>,
}

impl NotificationDispatch {
	pub fn new() -> Self {
		let (tx, _rx) = broadcast::channel(64);
		Self { tx }
	}

	pub fn subscribe(&self) -> NotificationStream {
		NotificationStream::new(self.tx.subscribe())
	}

	fn dispatch(&self, n: WalletNotification) {
		let _ = self.tx.send(n);
	}

	pub fn dispatch_movement_created(&self, movement: Movement) {
		self.dispatch(WalletNotification::MovementCreated { movement });
	}

	pub fn dispatch_movement_updated(&self, movement: Movement) {
		self.dispatch(WalletNotification::MovementUpdated { movement });
	}
}

impl Wallet {
	/// Subscribe to a stream of all movement updates
	///
	/// Returns a [`Stream`] that yields [Movement] items as they are whenever a
	/// movement is updated. Multiple subscribers can be active at the same
	/// time; each receives its own independent copy of every movement.
	///
	/// # Example
	///
	/// ```no_run
	/// use futures::StreamExt;
	///
	/// # async fn demo(wallet: &bark::Wallet) {
	/// let mut notifications = wallet.subscribe_notifications();
	/// while let Some(movement) = notifications.next().await {
	///     // handle movement
	/// }
	/// # }
	/// ```
	pub fn subscribe_notifications(&self) -> NotificationStream {
		self.notifications.subscribe()
	}
}
