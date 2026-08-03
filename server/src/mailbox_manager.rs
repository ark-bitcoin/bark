use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use tokio::sync::watch;

use ark::mailbox::MailboxIdentifier;

use crate::database::Checkpoint;

pub struct MailboxManager {
	map: parking_lot::RwLock<HashMap<MailboxIdentifier, watch::Sender<Checkpoint>>>,
}

impl MailboxManager {
	pub fn new() -> MailboxManager {
		MailboxManager {
			map: parking_lot::RwLock::new(HashMap::new()),
		}
	}

	/// Get a [MailboxSubscription] for the given mailbox.
	/// Creates the channel on first use with the initial value of parameter `init`.
	pub fn subscribe(self: &Arc<Self>, id: MailboxIdentifier, init: Checkpoint) -> MailboxSubscription {
		// read lock first
		{
			let map = self.map.read();
			if let Some(sender) = map.get(&id) {
				return MailboxSubscription {
					id: id,
					rx: sender.subscribe(),
					manager: self.clone(),
				};
			}
		}

		// upgrade to write lock
		let mut map = self.map.write();

		let sender = map.entry(id)
			.or_insert_with(|| watch::channel(init).0);

		MailboxSubscription {
			id: id,
			rx: sender.subscribe(),
			manager: self.clone(),
		}
	}

	/// Send a new checkpoint to all watchers of this mailbox
	/// If sending fails (no receivers), we immediately clean up the dead entry.
	pub fn notify(&self, id: MailboxIdentifier, cp: Checkpoint) {
		let read_guard = self.map.read();
		if let Some(sender) = read_guard.get(&id) {
			if sender.send(cp).is_err() {
				// no more receivers, so can be dropped from manager
				drop(read_guard);
				let mut write_guard = self.map.write();
				if let Some(sender) = write_guard.get(&id) {
					// just double-check no one inserted a new subscription since
					if sender.is_closed() {
						write_guard.remove(&id);
					}
				}
			}
		}
	}
}

/// A subscription to notifications for a single mailbox,
/// obtained through [MailboxManager::subscribe].
///
/// Dereferences to the underlying [watch::Receiver]. The last
/// subscription to be dropped removes the mailbox's entry from
/// the manager.
pub struct MailboxSubscription {
	id: MailboxIdentifier,
	rx: watch::Receiver<Checkpoint>,
	manager: Arc<MailboxManager>,
}

impl Deref for MailboxSubscription {
	type Target = watch::Receiver<Checkpoint>;

	fn deref(&self) -> &Self::Target {
		&self.rx
	}
}

impl DerefMut for MailboxSubscription {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.rx
	}
}

impl Drop for MailboxSubscription {
	fn drop(&mut self) {
		let mut map = self.manager.map.write();
		if let Some(sender) = map.get(&self.id) {
			// our own receiver still counts here; the write lock keeps
			// new subscriptions out until we're done
			if sender.receiver_count() <= 1 {
				map.remove(&self.id);
			}
		}
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use super::*;

	#[test]
	fn test_notify() {
		let mgr = Arc::new(MailboxManager::new());

		let id = MailboxIdentifier::from_str("02f6378a16b72df9316d7b933f631141d85f5554d38f2d94ba2a692e9fd1031d70").unwrap();

		let receiver = mgr.subscribe(id, 5);
		assert_eq!(*receiver.borrow(), 5);
		assert_eq!(*receiver.borrow(), 5);
		assert_eq!(mgr.map.read().len(), 1);
		mgr.notify(id, 7);
		assert_eq!(*receiver.borrow(), 7);
		assert_eq!(mgr.map.read().len(), 1);

		drop(receiver);
		assert_eq!(mgr.map.read().len(), 0);
	}

	#[test]
	fn test_drop_without_notify() {
		let mgr = Arc::new(MailboxManager::new());

		let id = MailboxIdentifier::from_str("02f6378a16b72df9316d7b933f631141d85f5554d38f2d94ba2a692e9fd1031d70").unwrap();

		let receiver = mgr.subscribe(id, 0);
		assert_eq!(mgr.map.read().len(), 1);
		drop(receiver);
		assert_eq!(mgr.map.read().len(), 0);
	}

	#[test]
	fn test_drop_keeps_entry_while_others_subscribed() {
		let mgr = Arc::new(MailboxManager::new());

		let id = MailboxIdentifier::from_str("02f6378a16b72df9316d7b933f631141d85f5554d38f2d94ba2a692e9fd1031d70").unwrap();

		let first = mgr.subscribe(id, 0);
		let second = mgr.subscribe(id, 0);
		assert_eq!(mgr.map.read().len(), 1);

		drop(first);
		assert_eq!(mgr.map.read().len(), 1);
		mgr.notify(id, 3);
		assert_eq!(*second.borrow(), 3);

		drop(second);
		assert_eq!(mgr.map.read().len(), 0);
	}
}
