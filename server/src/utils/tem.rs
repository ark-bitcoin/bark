//!
//! This module provides the [TimedEntryMap] type.
//!
//! This type exposes a map interface but keeps track of when each entry was inserted,
//! together with an easy interface to remove all entries older than a given duration.
//!
//! The type is not async-aware, so it has to be wrapped in a mutex or read-write lock
//! in order to be corrurrency-safe.
//!
#![allow(unused)]

use std::{fmt, iter, mem};
use std::borrow::Borrow;
use std::hash::Hash;
use std::time::{Duration, Instant};

use indexmap::IndexMap;


/// A map structure that tracks the time entries were inserted
///
/// The remove operation is quite costly, so could potentially be avoided,
/// in favor of letting elements expire naturally.
#[derive(Default)]
pub struct TimedEntryMap<K, V> {
	inner: IndexMap<K, (V, Instant)>,
}

impl<K, V> TimedEntryMap<K, V>
where
	K: Eq + Hash,
{
	/// Construct a new empty [TimedEntryMap]
	pub fn new() -> Self {
		Self {
			inner: IndexMap::new(),
		}
	}

	/// Construct a new [TimedEntryMap] with given capacity
	pub fn with_capacity(capacity: usize) -> Self {
		Self {
			inner: IndexMap::with_capacity(capacity),
		}
	}

	/// Get the number of entries
	pub fn len(&self) -> usize {
		self.inner.len()
	}

	/// Get an entry
	pub fn get<Q>(&self, key: &Q) -> Option<&V>
	where
		K: Borrow<Q>,
		Q: Eq + Hash + ?Sized,
	{
		self.inner.get(key).map(|(v, _t)| v)
	}

	/// Get a mutable entry
	pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
	where
		K: Borrow<Q>,
		Q: Eq + Hash + ?Sized,
	{
		self.inner.get_mut(key).map(|(v, _t)| v)
	}

	/// Insert a new entry
	pub fn insert(&mut self, key: K, value: V) -> Option<V> {
		self.inner.insert(key, (value, Instant::now())).map(|(v, _t)| v)
	}

	/// Remove an entry
	///
	/// This operation is quite costly in memory operations.
	pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
	where
		K: Borrow<Q>,
		Q: Hash + Eq + ?Sized,
	{
		self.inner.shift_remove(key).map(|(v, _t)| v)
	}

	/// Iterator over the values
	pub fn values(
		&self,
	) -> impl Iterator<Item = &V> + ExactSizeIterator + DoubleEndedIterator + Clone {
		self.inner.values().map(|(v, _t)| v)
	}

	/// Remove all entries before the given time
	///
	/// Returns an iterator over the removed items. The items will be removed
	/// immediatelly, even if the iterator is dropped.
	pub fn remove_before(&mut self, before: Instant) -> RemoveBefore<K, V> {
		let split_idx = match self.inner.binary_search_by(|_k, (_v, t)| t.cmp(&before)) {
			Ok(exact_idx) => exact_idx,
			Err(next_idx) => next_idx,
		};
		let mut split = self.inner.split_off(split_idx);
		// we actually want the other half
		mem::swap(&mut self.inner, &mut split);

		RemoveBefore {
			iter: split.into_iter(),
		}
	}

	/// Remove all entries older than the given duration
	///
	/// Returns an iterator over the removed items. The items will be removed
	/// immediatelly, even if the iterator is dropped.
	///
	/// Panics if duration is longer than the time since 1970.
	pub fn remove_older(&mut self, older_than: Duration) -> RemoveBefore<K, V> {
		let before = Instant::now().checked_sub(older_than)
			.expect("called remove_older with duration longer than time since 1970");
		self.remove_before(before)
	}
}

// some useful methods for maps where the value is an Option
impl<K, V> TimedEntryMap<K, Option<V>>
where
	K: Eq + Hash,
{
	/// Insert a new [Option::some] entry
	pub fn insert_some(&mut self, key: K, value: V) -> Option<V> {
		self.inner.insert(key, (Some(value), Instant::now())).map(|(mut v, _t)| v.take()).flatten()
	}

	/// Lookup an element for the given key, and return the result of [Option::take]
	///
	/// This will leave a [None] entry for the given key behind if an entry existed.
	pub fn take<Q>(&mut self, key: &Q) -> Option<V>
	where
		K: Borrow<Q>,
		Q: Eq + Hash + ?Sized,
	{
		self.get_mut(key).map(|opt| opt.take()).flatten()
	}
}

impl<K: Clone, V: Clone> Clone for TimedEntryMap<K, V> {
	fn clone(&self) -> Self {
	    Self {
			inner: self.inner.clone(),
		}
	}
}

impl<K: fmt::Debug, V: fmt::Debug> fmt::Debug for TimedEntryMap<K, V> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
	    f.debug_struct("TimedEntryMap")
			.field("inner", &self.inner)
			.finish()
	}
}

/// Iterator returned by [TimedEntryMap::remove_before]
pub struct RemoveBefore<K, V> {
	iter: indexmap::map::IntoIter<K, (V, Instant)>,
}

impl<K, V> Iterator for RemoveBefore<K, V> {
	type Item = (K, V);

	fn next(&mut self) -> Option<Self::Item> {
		self.iter.next().map(|(k, (v, _t))| (k, v))
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
	    self.iter.size_hint()
	}
}

impl<K, V> ExactSizeIterator for RemoveBefore<K, V> {
	fn len(&self) -> usize {
	    self.iter.len()
	}
}

impl<K, V> DoubleEndedIterator for RemoveBefore<K, V> {
	fn next_back(&mut self) -> Option<Self::Item> {
	    self.iter.next_back().map(|(k, (v, _))| (k, v))
	}
}

impl<K, V> iter::FusedIterator for RemoveBefore<K, V> {}


#[cfg(test)]
mod test {
	use std::thread::sleep;
	use std::time::Duration;
	use super::*;

	#[test]
	fn test_timed_entry_map() {
		let mut map = TimedEntryMap::<usize, usize>::new();

		map.insert(1, 11);
		map.insert(2, 22);

		sleep(Duration::from_millis(1));
		let t = Instant::now();
		sleep(Duration::from_millis(1));

		map.insert(3, 33);
		map.insert(4, 44);

		let mut r = map.remove_before(t);
		assert_eq!(r.next(), Some((1, 11)));
		assert_eq!(r.next(), Some((2, 22)));

		assert_eq!(map.len(), 2);
		assert_eq!(map.get(&3), Some(&33));
		assert_eq!(map.get(&4), Some(&44));
	}
}
