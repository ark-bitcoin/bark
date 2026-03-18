//! In-memory implementation of the `StorageAdaptor` trait.
//!
//! This module provides a simple in-memory storage adaptor for testing
//! and ephemeral use cases, along with a reusable test suite for validating
//! any `StorageAdaptor` implementation.

use std::collections::{BTreeMap, HashMap};

use crate::persist::adaptor::{Query, QueryRange, Record, StorageAdaptor, StorageAdaptorWrapper};

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
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = StorageAdaptorWrapper::new_memory();
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

impl StorageAdaptorWrapper<MemoryStorageAdaptor> {
	pub fn new_memory() -> Self {
		Self::new(MemoryStorageAdaptor::new())
	}
}

#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
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

	async fn query_sorted<R: QueryRange>(&self, query: Query<R>) -> anyhow::Result<Vec<Record>> {
		let Some(partition) = self.partitions.get(&query.partition) else {
			return Ok(Vec::new());
		};

		let mut results: Vec<_> = partition
			.values()
			.filter(|r| {
				// Records without sort keys are excluded from query results
				let Some(sort_key) = &r.sort_key else {
					return false;
				};

				query.range.contains(sort_key)
			})
			.cloned()
			.collect();

		// Sort by sort key (all records have sort keys at this point)
		results.sort_by(|a, b| {
			match (&a.sort_key, &b.sort_key) {
				(Some(ka), Some(kb)) => ka.cmp(kb),
				_ => unreachable!("all records should have sort keys after filtering"),
			}
		});

		// Apply limit
		if let Some(limit) = query.limit {
			results.truncate(limit);
		}

		Ok(results)
	}

	async fn get_all(&self, partition: u8) -> anyhow::Result<Vec<Record>> {
		let Some(partition_map) = self.partitions.get(&partition) else {
			return Ok(Vec::new());
		};

		Ok(partition_map.values().cloned().collect())
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
