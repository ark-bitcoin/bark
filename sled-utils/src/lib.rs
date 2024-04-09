use std::collections::HashSet;
use std::hash::Hash;
use std::marker::PhantomData;

/// Iterates over the items in a [BucketTree].
pub struct BucketTreeIter<T> {
	iter: sled::Iter,
	_pd: PhantomData<T>,
}

impl<T: serde::de::DeserializeOwned + Eq + Hash> Iterator for BucketTreeIter<T> {
	type Item = Result<(sled::IVec, HashSet<T>), sled::Error>;

	fn next(&mut self) -> Option<Self::Item> {
		match self.iter.next()? {
			Ok((key, value)) => {
				let set = ciborium::from_reader(&value[..]).expect("corrupt db: invalid set");
				Some(Ok((key, set)))
			},
			Err(e) => Some(Err(e)),
		}
	}
}

/// A sled [Tree] in which each value is a set of individual items of type [T].
///
/// When an item is inserted twice, it has no effect and when the last item of
/// the set is removed, the key is dropped from the tree.
pub struct BucketTree<'a, T> {
	tree: &'a sled::transaction::TransactionalTree,
	_pd: PhantomData<T>,
}

impl<'a, T: serde::de::DeserializeOwned + serde::Serialize + Eq + Hash + Clone> BucketTree<'a, T> {
	/// Create a new [BucketTree] by wrapping a [Tree].
	pub fn new(tree: &'a sled::transaction::TransactionalTree) -> BucketTree<T> {
		Self {
			tree: tree,
			_pd: PhantomData,
		}
	}

	pub fn insert(
		&self,
		key: impl AsRef<[u8]>,
		item: &T,
	) -> Result<bool, sled::transaction::UnabortableTransactionError> {
		let mut set = if let Some(buf) = self.tree.get(&key)? {
			ciborium::from_reader(&buf[..]).expect("corrupt db: invalid set")
		} else {
			HashSet::new()
		};

		let old_len = set.len();
		let ret = set.insert(item.clone());

		// naively extrapolate the set's size
		let item_len = if set.len() == 1 {
			0 // can't know
		} else {
			old_len / (set.len() - 1)
		};
		let mut buf = Vec::with_capacity(old_len + item_len);
		ciborium::into_writer(&set, &mut buf).expect("bufs don't error");

		self.tree.insert(key.as_ref(), buf)?;
		Ok(ret)
	}

	pub fn remove(
		&self,
		key: impl AsRef<[u8]>,
		item: &T,
	) -> Result<bool, sled::transaction::UnabortableTransactionError> {
		let mut set = if let Some(buf) = self.tree.get(&key)? {
			ciborium::from_reader::<HashSet<T>, _>(&buf[..]).expect("corrupt db: invalid set")
		} else {
			return Ok(false);
		};

		let old_len = set.len();
		let ret = set.remove(item);

		if !set.is_empty() {
			let mut buf = Vec::with_capacity(old_len);
			ciborium::into_writer(&set, &mut buf).expect("bufs don't error");
			self.tree.insert(key.as_ref(), buf)?;
		} else {
			self.tree.remove(key.as_ref())?;
		}
		Ok(ret)
	}
	//
	// /// Iterate over all the items in the [BucketTree].
	// pub fn iter(&self) -> BucketTreeIter<T> {
	// 	BucketTreeIter {
	// 		iter: self.tree.iter(),
	// 		_pd: PhantomData,
	// 	}
	// }
}
