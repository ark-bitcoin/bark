use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use crate::Wallet;
use crate::persist::models::{RoundStateId, StoredRoundState};

#[derive(Clone)]
pub(crate) struct RoundStateLockIndex {
	locked: Arc<parking_lot::Mutex<HashSet<RoundStateId>>>,
}

impl RoundStateLockIndex {
	pub fn new() -> Self {
		Self {
			locked: Arc::new(parking_lot::Mutex::new(HashSet::new())),
		}
	}

	pub(crate) fn try_lock(&self, round_state: RoundStateId) -> Option<RoundStateGuard> {
		let mut index_lock = self.locked.lock();
		if index_lock.insert(round_state) {
			Some(RoundStateGuard { index: self.clone(), round_state })
		} else {
			None
		}
	}

	/// Try to lock the given round state, waiting until it becomes available.
	pub(crate) async fn wait_lock(&self, round_state: RoundStateId) -> anyhow::Result<RoundStateGuard> {
		let mut attempts = 0;
		loop {
			if let Some(guard) = self.try_lock(round_state) {
				return Ok(guard);
			}
			attempts += 1;
			// tries for 10 seconds, enough for a round to complete
			if attempts > 100 {
				bail!("Timed out waiting for lock on round state {}", round_state);
			}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
	}
}

pub struct RoundStateGuard {
	index: RoundStateLockIndex,
	round_state: RoundStateId,
}

impl std::ops::Drop for RoundStateGuard {
	fn drop(&mut self) {
		self.index.locked.lock().remove(&self.round_state);
	}
}

impl Wallet {
	/// Load and lock a single given round state (by id), waiting for the lock.
	///
	/// Returns `Some(state, guard)` if the round state is found and locked, `None`
	/// if it is not found after waiting for the lock.
	pub async fn lock_wait_round_state(&self, id: RoundStateId) -> anyhow::Result<Option<StoredRoundState>> {
		let guard = self.round_state_lock_index.wait_lock(id).await?;

		if let Some(state) = self.db.get_round_state_by_id(id).await? {
			return Ok(Some(state.lock(guard)));
		}

		Ok(None)
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn round_state_lock() {
		let index = RoundStateLockIndex::new();

		// returns guard on first acquisition
		let guard = index.try_lock(RoundStateId(1));
		assert!(guard.is_some(), "first lock should succeed");

		// returns none on second acquisition
		let guard2 = index.try_lock(RoundStateId(1));
		assert!(guard2.is_none(), "second lock should fail");

		// dropping guard releases lock
		drop(guard);
		assert!(index.try_lock(RoundStateId(1)).is_some(), "lock should succeed after drop");

		// different ids lock independently
		let guard3 = index.try_lock(RoundStateId(2));
		assert!(guard3.is_some(), "second lock should succeed");

		// cloned index shares lock state
		let cloned = index.clone();
		let id = RoundStateId(1);
		let guard4 = cloned.try_lock(id);
		assert!(guard4.is_some(), "cloned index should share lock state");
		assert!(index.try_lock(id).is_none(), "original should prevent lock");

		// dropping guard releases lock
		drop(guard4);
		let guard5 = index.try_lock(id);
		assert!(guard5.is_some(), "lock should succeed on original index after drop");
		assert!(cloned.try_lock(id).is_none(), "cloned index should prevent lock");
	}

	#[tokio::test]
	async fn lock_wait_succeeds_after_guard_dropped() {
		let index = RoundStateLockIndex::new();
		let guard = index.try_lock(RoundStateId(1)).unwrap();

		let cloned = index.clone();
		let handle = tokio::spawn(async move {
			cloned.wait_lock(RoundStateId(1)).await
		});

		// Release after a short delay so lock_wait can acquire it.
		tokio::time::sleep(Duration::from_millis(150)).await;
		drop(guard);

		let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
		assert!(result.is_ok(), "lock_wait should complete after guard is dropped");
	}
}
