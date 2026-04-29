
use std::borrow::Cow;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, MutexGuard, OwnedMutexGuard};


/// A [`tokio::sync::Mutex`] wrapper that emits `slog` events when the lock
/// is acquired and released.
///
/// - `LockAcquired` carries the wait time (how long the caller spent
///   awaiting `lock()`).
/// - `LockReleased` carries the hold time (how long the guard was alive).
///
/// Both events carry the lock's `name`. Cheap to clone — clones share the
/// underlying mutex.
pub struct InstrumentedLock<T> {
	name: Cow<'static, str>,
	inner: Arc<Mutex<T>>,
}

impl<T> Clone for InstrumentedLock<T> {
	fn clone(&self) -> Self {
		Self { name: self.name.clone(), inner: self.inner.clone() }
	}
}

impl<T> InstrumentedLock<T> {
	pub fn new(name: impl Into<Cow<'static, str>>, value: T) -> Self {
		Self { name: name.into(), inner: Arc::new(Mutex::new(value)) }
	}

	pub fn name(&self) -> &str {
		&self.name
	}

	#[tracing::instrument(skip(self), fields(lock = %self.name))]
	pub async fn lock(&self) -> InstrumentedLockGuard<'_, T> {
		let started = Instant::now();
		let guard = self.inner.lock().await;
		let waited = started.elapsed();
		slog!(LockAcquired, name: self.name.clone(), waited);
		InstrumentedLockGuard {
			name: self.name.clone(),
			held_since: Instant::now(),
			inner: guard,
		}
	}

	#[tracing::instrument(skip(self), fields(lock = %self.name))]
	pub async fn lock_owned(&self) -> InstrumentedOwnedLockGuard<T> {
		let started = Instant::now();
		let guard = self.inner.clone().lock_owned().await;
		let waited = started.elapsed();
		slog!(LockAcquired, name: self.name.clone(), waited);
		InstrumentedOwnedLockGuard {
			name: self.name.clone(),
			held_since: Instant::now(),
			inner: guard,
		}
	}
}

pub struct InstrumentedLockGuard<'a, T> {
	name: Cow<'static, str>,
	held_since: Instant,
	inner: MutexGuard<'a, T>,
}

impl<'a, T> Deref for InstrumentedLockGuard<'a, T> {
	type Target = T;
	fn deref(&self) -> &T {
		&self.inner
	}
}

impl<'a, T> DerefMut for InstrumentedLockGuard<'a, T> {
	fn deref_mut(&mut self) -> &mut T {
		&mut self.inner
	}
}

impl<'a, T> Drop for InstrumentedLockGuard<'a, T> {
	fn drop(&mut self) {
		let held = self.held_since.elapsed();
		slog!(LockReleased, name: self.name.clone(), held);
	}
}

pub struct InstrumentedOwnedLockGuard<T> {
	name: Cow<'static, str>,
	held_since: Instant,
	inner: OwnedMutexGuard<T>,
}

impl<T> Deref for InstrumentedOwnedLockGuard<T> {
	type Target = T;
	fn deref(&self) -> &T {
		&self.inner
	}
}

impl<T> DerefMut for InstrumentedOwnedLockGuard<T> {
	fn deref_mut(&mut self) -> &mut T {
		&mut self.inner
	}
}

impl<T> Drop for InstrumentedOwnedLockGuard<T> {
	fn drop(&mut self) {
		let held = self.held_since.elapsed();
		slog!(LockReleased, name: self.name.clone(), held);
	}
}
