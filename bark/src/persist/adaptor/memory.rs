//! In-memory implementation of the `StorageAdaptor` trait.
//!
//! This module provides a simple in-memory storage adaptor for testing
//! and ephemeral use cases, along with a reusable test suite for validating
//! any `StorageAdaptor` implementation.

use std::collections::{BTreeMap, HashMap};

use crate::persist::adaptor::{StorageAdaptor, Query, Record};

/// In-memory storage adaptor for testing and simple use cases.
///
/// This implementation stores records in partition-keyed `HashMap`s.
/// Each partition has its own map.
///
/// # Example
///
/// ```rust
/// # use bitcoin::Network;
/// # use bitcoin::bip32::Fingerprint;
/// # use bark::WalletProperties;
/// # use bark::persist::BarkPersister;
/// # use bark::persist::adaptor::StorageAdaptorWrapper;
/// # use bark::persist::adaptor::memory::MemoryStorageAdaptor;
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = StorageAdaptorWrapper::new(MemoryStorageAdaptor::new());
/// let properties = WalletProperties {
///		network: Network::Testnet,
///		fingerprint: Fingerprint::default(),
///		server_pubkey: None,
///	};
///
/// storage.init_wallet(&properties).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Default)]
pub struct MemoryStorageAdaptor {
	/// Map from partition -> (pk -> record)
	partitions: HashMap<u8, BTreeMap<Vec<u8>, Record>>,
}

impl MemoryStorageAdaptor {
	/// Creates a new empty in-memory storage.
	pub fn new() -> Self {
		Self::default()
	}

	pub fn partitions(&self) -> &HashMap<u8, BTreeMap<Vec<u8>, Record>> {
		&self.partitions
	}
}

#[async_trait]
impl StorageAdaptor for MemoryStorageAdaptor {
	async fn put(&mut self, record: Record) -> anyhow::Result<()> {
		let partition = self.partitions.entry(record.partition).or_default();
		partition.insert(record.pk.clone(), record);
		Ok(())
	}

	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		if let Some(partition) = self.partitions.get(&partition) {
			if let Some(record) = partition.get(pk) {
				return Ok(Some(record.clone()));
			}
		}
		Ok(None)
	}

	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>> {
		if let Some(partition) = self.partitions.get_mut(&partition) {
			return Ok(partition.remove(pk))
		}

		Ok(None)
	}

	async fn query(&self, query: Query) -> anyhow::Result<Vec<Record>> {
		let Some(partition) = self.partitions.get(&query.partition) else {
			return Ok(Vec::new());
		};

		let mut results: Vec<_> = partition
			.values()
			.filter(|r| {
				let matches_start = if let Some(start) = &query.start {
					match &r.sort_key {
						Some(sort_key) => sort_key.cmp(start) >= std::cmp::Ordering::Equal,
						None => false,
					}
				} else { true };

				let matches_end = if let Some(end) = &query.end {
					match &r.sort_key {
						Some(sort_key) => sort_key.cmp(end) <= std::cmp::Ordering::Equal,
						None => false,
					}
				} else { true };

				matches_start && matches_end
			})
			.cloned()
			.collect();

		// Sort by sort key
		results.sort_by(|a, b| {
			match (&a.sort_key, &b.sort_key) {
				(Some(ka), Some(kb)) => ka.cmp(kb),
				(Some(_), None) => std::cmp::Ordering::Less,
				(None, Some(_)) => std::cmp::Ordering::Greater,
				(None, None) => std::cmp::Ordering::Equal,
			}
		});

		// Apply limit
		if let Some(limit) = query.limit {
			results.truncate(limit);
		}

		Ok(results)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::persist::adaptor::test_suite;

	/// Run the full test suite against MemoryStorageAdaptor.
	#[tokio::test]
	async fn memory_adaptor_full_test_suite() {
		let mut storage = MemoryStorageAdaptor::new();
		test_suite::run_all(&mut storage).await;
	}
}
