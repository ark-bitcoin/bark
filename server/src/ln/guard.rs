//! A lock on one payment hash.
//!
//! [`PaymentGuards::lock`] takes the lock and returns a [`PaymentGuard`]. No
//! other task can lock the same payment hash while that guard exists. The lock
//! is free again when the guard is dropped.
//!
//! Each payment hash has its own lock. A payment never waits for a different
//! payment.
//!
//! The lock is fair. Callers receive it in the order that they ask for it. A
//! late caller never passes a caller that arrived before it.
//!
//! A caller can stop the wait. Drop the future of the call. The caller leaves
//! the queue and the other callers keep their order.

use std::collections::HashMap;
use std::sync::{Arc, Weak};

use tokio::sync::Semaphore;

use ark::lightning::PaymentHash;


/// The payment hash locks of the server.
///
/// This is a handle. A clone of it uses the same locks.
#[derive(Debug, Clone)]
pub struct PaymentGuards {
	locks: Arc<Locks>,
}

impl PaymentGuards {
	pub fn new() -> PaymentGuards {
		PaymentGuards { locks: Arc::new(Locks::default()) }
	}

	/// Takes the lock on the payment hash.
	///
	/// The call waits until the current holder drops its guard. The call is
	/// safe to cancel.
	pub async fn lock(&self, payment_hash: PaymentHash) -> PaymentGuard {
		let mut waiting = Waiting {
			locks: &self.locks,
			payment_hash,
			semaphore: self.locks.semaphore(payment_hash),
			acquired: false,
		};

		// The semaphore is never closed.
		let permit = waiting.semaphore.acquire().await
			.expect("the semaphore is never closed");

		// The permit is returned by hand in `PaymentGuard::drop`. This is what
		// permits the guard to outlive this call.
		permit.forget();
		waiting.acquired = true;

		PaymentGuard {
			locks: self.locks.clone(),
			payment_hash,
			semaphore: waiting.semaphore.clone(),
		}
	}

	/// The number of payment hashes that are locked or waited for.
	///
	/// For tests and diagnostics.
	pub fn tracked(&self) -> usize {
		self.locks.map.lock().len()
	}
}

/// The lock of each payment hash that a caller uses.
///
/// The map holds a weak reference to each lock, and the callers hold the strong
/// references. A lock therefore lives exactly as long as a caller uses it, and
/// the last caller to leave removes it from the map.
#[derive(Debug, Default)]
struct Locks {
	map: parking_lot::Mutex<HashMap<PaymentHash, Weak<Semaphore>>>,
}

impl Locks {
	/// The lock of the payment hash, and a new lock if no caller uses it.
	///
	/// A weak reference upgrades while a caller uses the lock. The new caller
	/// must receive that same lock, because a second lock would let two callers
	/// hold one payment hash at once.
	fn semaphore(&self, payment_hash: PaymentHash) -> Arc<Semaphore> {
		let mut map = self.map.lock();
		if let Some(semaphore) = map.get(&payment_hash).and_then(Weak::upgrade) {
			return semaphore;
		}

		let semaphore = Arc::new(Semaphore::new(1));
		map.insert(payment_hash, Arc::downgrade(&semaphore));
		semaphore
	}

	/// Removes the payment hash, if the caller that leaves is the last user.
	///
	/// The count is the number of strong references to the lock. The map holds a
	/// weak reference, so the map never counts. Each caller that holds the lock
	/// or waits for it holds one strong reference, and this function always runs
	/// from such a caller.
	///
	/// A count of 1 therefore means that no other caller is left, and the map
	/// can forget the payment hash. A higher count means that another caller
	/// holds the lock or waits for it, and that caller removes the payment hash
	/// when it leaves.
	///
	/// The map is locked for the whole check. A new caller can only reach the
	/// lock through [`Locks::semaphore`], which needs the same map lock, so the
	/// count cannot grow while it is read.
	fn remove_if_last(&self, payment_hash: PaymentHash, semaphore: &Arc<Semaphore>) {
		let mut map = self.map.lock();
		// The single holder of the Arc is this task.
		if Arc::strong_count(semaphore) == 1 {
			map.remove(&payment_hash);
		}
	}
}

/// A caller in the queue for a payment hash.
///
/// The caller leaves the queue if it is dropped before the lock is granted. It
/// receives no guard, so it must remove the payment hash itself.
struct Waiting<'a> {
	locks: &'a Locks,
	payment_hash: PaymentHash,
	semaphore: Arc<Semaphore>,
	/// True after the lock is granted. From that moment the guard is the caller
	/// that removes the payment hash.
	acquired: bool,
}

impl Drop for Waiting<'_> {
	fn drop(&mut self) {
		if !self.acquired {
			self.locks.remove_if_last(self.payment_hash, &self.semaphore);
		}
	}
}

/// A lock on one payment hash.
///
/// The lock is free again when the guard is dropped, and not before.
pub struct PaymentGuard {
	locks: Arc<Locks>,
	payment_hash: PaymentHash,
	semaphore: Arc<Semaphore>,
}

impl PaymentGuard {
	/// The payment hash that this guard locks.
	pub fn payment_hash(&self) -> PaymentHash {
		self.payment_hash
	}
}

impl Drop for PaymentGuard {
	fn drop(&mut self) {
		// This gives the lock to the caller that waits the longest, if there is
		// one. That caller holds a strong reference, which is what keeps the
		// payment hash in the map.
		self.semaphore.add_permits(1);
		self.locks.remove_if_last(self.payment_hash, &self.semaphore);
	}
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
	use std::time::Duration;

	use super::*;

	fn hash(n: u8) -> PaymentHash {
		PaymentHash::from([n; 32])
	}

	/// Polls a lock one time and does not wait for it.
	///
	/// Returns the guard if the lock is granted. The first call puts the caller
	/// in the queue. Use this function in sequence to put callers in a known
	/// order.
	async fn poll(waiting: &mut std::pin::Pin<Box<impl Future<Output = PaymentGuard>>>)
		-> Option<PaymentGuard>
	{
		tokio::time::timeout(Duration::ZERO, waiting).await.ok()
	}

	#[tokio::test]
	async fn a_guard_holds_the_hash_it_locked() {
		let guards = PaymentGuards::new();
		let guard = guards.lock(hash(1)).await;

		assert_eq!(guard.payment_hash(), hash(1));
	}

	#[tokio::test]
	async fn a_second_lock_on_one_payment_waits_for_the_first() {
		let guards = PaymentGuards::new();
		let first = guards.lock(hash(1)).await;

		let mut second = Box::pin(guards.lock(hash(1)));
		assert!(poll(&mut second).await.is_none(), "the second lock must wait for the first");

		drop(first);
		assert!(poll(&mut second).await.is_some(), "the lock is granted after the first is dropped");
	}

	#[tokio::test]
	async fn locks_on_different_payments_do_not_wait() {
		let guards = PaymentGuards::new();
		let _first = guards.lock(hash(1)).await;

		let mut second = Box::pin(guards.lock(hash(2)));
		assert!(poll(&mut second).await.is_some(), "a different payment hash is not blocked");
	}

	/// The lock goes to the caller that waits the longest, and not to the caller
	/// that is polled first. Each step polls the last caller in the queue first,
	/// and that caller never receives the lock.
	#[tokio::test]
	async fn the_lock_is_granted_in_order_of_arrival() {
		let guards = PaymentGuards::new();
		let held = guards.lock(hash(1)).await;

		// One poll per caller puts the callers in a known order.
		let mut queue = Vec::new();
		for _ in 0..5 {
			let mut waiting = Box::pin(guards.lock(hash(1)));
			assert!(poll(&mut waiting).await.is_none(), "the lock is held");
			queue.push(waiting);
		}

		drop(held);
		for n in 0..5 {
			let (first_in_line, rest) = queue[n..].split_first_mut().expect("the caller is in the queue");
			if let Some(last) = rest.last_mut() {
				assert!(poll(last).await.is_none(), "a late caller does not pass an early one");
			}

			let granted = poll(first_in_line).await.expect("the longest wait is served first");
			drop(granted);
		}
	}

	/// Two tasks never hold one payment hash at the same time.
	#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
	async fn one_payment_is_never_locked_twice_at_once() {
		let guards = PaymentGuards::new();
		let inside = Arc::new(AtomicBool::new(false));
		let visits = Arc::new(AtomicUsize::new(0));

		let mut tasks = Vec::new();
		for _ in 0..8 {
			let guards = guards.clone();
			let inside = inside.clone();
			let visits = visits.clone();
			tasks.push(tokio::spawn(async move {
				for _ in 0..50 {
					let guard = guards.lock(hash(1)).await;
					assert!(!inside.swap(true, Ordering::SeqCst), "two tasks hold one payment hash");
					// A yield here gives another task the chance to enter.
					tokio::task::yield_now().await;
					visits.fetch_add(1, Ordering::SeqCst);
					inside.store(false, Ordering::SeqCst);
					drop(guard);
				}
			}));
		}
		for task in tasks {
			task.await.expect("join the task");
		}

		assert_eq!(visits.load(Ordering::SeqCst), 400);
		assert_eq!(guards.tracked(), 0, "no lock remains");
	}

	#[tokio::test]
	async fn a_released_payment_is_not_tracked() {
		let guards = PaymentGuards::new();

		let first = guards.lock(hash(1)).await;
		let second = guards.lock(hash(2)).await;
		assert_eq!(guards.tracked(), 2);

		drop(first);
		assert_eq!(guards.tracked(), 1, "the lock of a released payment is removed");

		drop(second);
		assert_eq!(guards.tracked(), 0, "no lock remains");
	}

	/// A payment hash that a caller waits for keeps its lock. A new lock would
	/// give the next caller access to a payment that another caller holds.
	#[tokio::test]
	async fn a_waited_on_payment_keeps_its_entry() {
		let guards = PaymentGuards::new();
		let held = guards.lock(hash(1)).await;

		let mut waiting = Box::pin(guards.lock(hash(1)));
		assert!(poll(&mut waiting).await.is_none(), "the lock is held");

		drop(held);
		let granted = poll(&mut waiting).await.expect("the caller receives the same lock");
		assert_eq!(guards.tracked(), 1);

		drop(granted);
		assert_eq!(guards.tracked(), 0);
	}

	/// A caller that gives up in the queue leaves the lock to the other callers.
	#[tokio::test]
	async fn a_waiter_that_gives_up_leaves_the_queue() {
		let guards = PaymentGuards::new();
		let held = guards.lock(hash(1)).await;

		let mut giving_up = Box::pin(guards.lock(hash(1)));
		assert!(poll(&mut giving_up).await.is_none(), "the lock is held");
		let mut staying = Box::pin(guards.lock(hash(1)));
		assert!(poll(&mut staying).await.is_none(), "the lock is held");

		// The first caller in the queue gives up, so the next caller moves up.
		drop(giving_up);
		drop(held);

		let granted = poll(&mut staying).await.expect("the remaining caller receives the lock");
		assert_eq!(granted.payment_hash(), hash(1));
		drop(granted);
		assert_eq!(guards.tracked(), 0, "no lock remains");
	}

	/// A caller that gives up frees the lock, even though it never held it and
	/// received no guard.
	#[tokio::test]
	async fn the_last_caller_to_give_up_frees_the_lock() {
		let guards = PaymentGuards::new();
		let held = guards.lock(hash(1)).await;

		let mut giving_up = Box::pin(guards.lock(hash(1)));
		assert!(poll(&mut giving_up).await.is_none(), "the lock is held");

		drop(held);
		assert_eq!(guards.tracked(), 1, "a caller is still in the queue");

		drop(giving_up);
		assert_eq!(guards.tracked(), 0, "no lock remains");
	}

	/// A task can hold the guard across an await point.
	#[test]
	fn a_guard_can_be_held_by_a_spawned_task() {
		fn assert_send_static<T: Send + Sync + 'static>() {}
		assert_send_static::<PaymentGuard>();
		assert_send_static::<PaymentGuards>();
	}

}
