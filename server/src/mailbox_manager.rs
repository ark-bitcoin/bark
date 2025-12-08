use std::collections::HashMap;
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

	/// Get a watch::Receiver for the given mailbox.
	/// Creates the channel on first use with the initial value of parameter `init`.
	pub fn subscribe(&self, id: MailboxIdentifier, init: Checkpoint) -> watch::Receiver<Checkpoint> {
		// read lock first
		{
			let map = self.map.read();
			if let Some(sender) = map.get(&id) {
				return sender.subscribe();
			}
		}

		// upgrade to write lock
		let mut map = self.map.write();

		let sender = map.entry(id)
			.or_insert_with(|| watch::channel(init).0);

		sender.subscribe()
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

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use super::*;

	#[test]
	fn test_notify() {
		let mgr = MailboxManager::new();

		let id = MailboxIdentifier::from_str("02f6378a16b72df9316d7b933f631141d85f5554d38f2d94ba2a692e9fd1031d70").unwrap();

		let receiver = mgr.subscribe(id, 5);
		assert_eq!(*receiver.borrow(), 5);
		assert_eq!(*receiver.borrow(), 5);
		assert_eq!(mgr.map.read().len(), 1);
		mgr.notify(id, 7);
		assert_eq!(*receiver.borrow(), 7);
		assert_eq!(mgr.map.read().len(), 1);

		drop(receiver);
		assert_eq!(mgr.map.read().len(), 1);
		mgr.notify(id, 9);
		assert_eq!(mgr.map.read().len(), 0);
	}
}
