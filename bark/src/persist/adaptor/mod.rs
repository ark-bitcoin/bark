//! Storage adaptor module providing the [StorageAdaptor] trait and blanket
//! implementation of [BarkPersister] for any type implementing [StorageAdaptor].
//!
//! This module provides an optimized single-table storage abstraction that can be
//! efficiently implemented on various backends (SQLite, Postgres, MongoDB, Firebase,
//! in-memory, etc.).
//!
//! The design uses structured keys:
//! - **Primary key (`pk`)**: Unique identifier for each record
//! - **Partition key**: Groups related records for efficient querying
//! - **Sort key**: Enables ordered iteration and range queries
//! ```

mod sort;

pub use sort::SortKey;

use serde::{de::DeserializeOwned, Serialize};

pub mod partition {
	pub const PROPERTIES: u8 = 0;
	pub const BDK_CHANGESET: u8 = 1;
	pub const VTXO: u8 = 2;
	pub const PUBLIC_KEY: u8 = 3;
	pub const PENDING_BOARD: u8 = 4;
	pub const ROUND_STATE: u8 = 5;
	pub const MOVEMENT: u8 = 6;
	pub const LIGHTNING_SEND: u8 = 7;
	pub const LIGHTNING_RECEIVE: u8 = 8;
	pub const EXIT_VTXO: u8 = 9;
	pub const EXIT_CHILD_TX: u8 = 10;

	pub const LAST_IDS: u8 = u8::MAX;
}

/// A storage record with structured keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
	/// Partition key for grouping related records (e.g., "vtxo", "movement").
	///
	/// Queries always filter by partition.
	pub partition: u8,

	/// Unique primary key
	pub pk: Vec<u8>,

	/// Optional sort key for ordered iteration within a partition.
	///
	/// Use [`SortKey::builder()`] to construct composite keys with
	/// mixed sort directions.
	///
	/// This field may be set or changed after record insertion.
	/// Implementation should support updating the sort key of a
	/// record post-insert if needed.
	pub sort_key: Option<SortKey>,

	/// The record data encoded as JSON.
	pub data: Vec<u8>,
}

impl Record {
	/// Converts the record data to a typed value.
	fn to_data<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
		serde_json::from_slice(&self.data).map_err(Into::into)
	}

	/// Creates a new record from a typed value.
	fn from_data<T: Serialize>(
		partition: u8,
		pk: &[u8],
		sort_key: Option<SortKey>,
		data: &T,
	) -> anyhow::Result<Record> {
		Ok(Record {
			partition,
			pk: pk.to_vec(),
			sort_key,
			data: serde_json::to_vec(data)?,
		})
	}
}

/// Query specification for retrieving records from a partition.
#[derive(Debug, Clone, Default)]
pub struct Query {
	/// Partition to query (required).
	pub partition: u8,

	/// Include historical records. Default: `false` (current records only).
	pub include_history: bool,

	/// Maximum number of records to return.
	pub limit: Option<usize>,

	/// Inclusive start key for the query.
	pub start: Option<SortKey>,

	/// Exclusive end key for the query.
	pub end: Option<SortKey>,
}

impl Query {
	/// Creates a new query for the given partition.
	pub fn new(partition: u8) -> Self {
		Self {
			partition,
			..Default::default()
		}
	}

	/// Includes historical records in the results.
	pub fn include_history(mut self) -> Self {
		self.include_history = true;
		self
	}

	/// Limits the number of results.
	pub fn limit(mut self, n: usize) -> Self {
		self.limit = Some(n);
		self
	}

	/// Sets the start key for the query (inclusive).
	pub fn start(mut self, start: SortKey) -> Self {
		self.start = Some(start);
		self
	}

	/// Sets the end key for the query (exclusive).
	pub fn end(mut self, end: SortKey) -> Self {
		self.end = Some(end);
		self
	}
}

/// Storage adaptor trait for persistence backends.
///
/// This trait provides a minimal interface (4 methods) that can be efficiently
/// implemented on various storage backends while enabling query optimization.
///
/// # Implementor's Guide
///
/// ## Simple backends (memory, file-based)
///
/// Store records in a map/list and implement `query` by filtering in memory.
///
/// ## Database backends (Postgres, MongoDB, Firebase, IndexedDB, etc.)
///
/// Create a single table with indexes:
///
/// ```sql
/// CREATE TABLE storage (
///     pk TEXT PRIMARY KEY,
///     partition TEXT NOT NULL,
///     sort_key BLOB,
///     data BLOB NOT NULL
/// );
/// CREATE INDEX idx_partition_sort ON storage(partition, sort_key);
/// ```
///
/// Translate [`Query`] to SQL:
///
/// ```sql
/// SELECT * FROM storage
/// WHERE partition = :partition
/// ORDER BY :sort_key DESC
/// ```
#[async_trait]
pub trait StorageAdaptor: Send + Sync + 'static {
	/// Stores a record, inserting or updating by primary key.
	async fn put(&mut self, record: Record) -> anyhow::Result<()>;

	/// Retrieves a record by primary key.
	///
	/// Returns `None` if the record doesn't exist.
	async fn get(&self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>>;

	/// Deletes a record by primary key.
	///
	/// Returns the deleted record if it existed, `None` otherwise.
	async fn delete(&mut self, partition: u8, pk: &[u8]) -> anyhow::Result<Option<Record>>;

	/// Queries records in a partition
	///
	/// Results are ordered by sort key. Records without a sort key appear last.
	async fn query(&self, query: Query) -> anyhow::Result<Vec<Record>>;

	/// Increments the last partition id, then stores and returns the new id.
	async fn incremental_id(&mut self, partition: u8) -> anyhow::Result<u32> {
		let last_partition_id = self.get(partition::LAST_IDS, &[partition]).await?
			.map(|r| r.to_data::<u32>()).unwrap_or(Ok(0))?;
		let next_partition_id = last_partition_id + 1;

		let record = Record::from_data(
			partition::LAST_IDS,
			&[partition],
			None,
			&next_partition_id,
		)?;

		self.put(record).await?;
		Ok(next_partition_id)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn storage_query_builder() {
		let query = Query::new(0)
			.include_history()
			.limit(10)
			.start(SortKey::u32_asc(100))
			.end(SortKey::u32_asc(200));

		assert_eq!(query.partition, 0);
		assert!(query.include_history);
		assert_eq!(query.limit, Some(10));
		assert_eq!(query.start, Some(SortKey::u32_asc(100)));
		assert_eq!(query.end, Some(SortKey::u32_asc(200)));
	}
}

/// This module provides comprehensive tests for all four methods of the
/// `StorageAdaptor` trait. Use these functions to validate custom implementations.
///
/// # Example
///
/// ```rust
/// use bark::persist::adaptor::memory::test_suite;
///
/// #[tokio::test]
/// async fn test_my_custom_adaptor() {
///     let storage = MyCustomStorageAdaptor::new();
///     test_suite::run_all(&storage).await;
/// }
/// ```
#[cfg(test)]
pub mod test_suite {
	use super::*;
	use super::partition::LAST_IDS;
	use super::sort::SortKey;

	async fn clear_partitions<S: StorageAdaptor>(storage: &mut S, partitions: &[u8]) -> anyhow::Result<()> {
		for partition in partitions {
			let records = storage.query(Query::new(*partition).include_history()).await?;
			for record in records {
				storage.delete(record.partition, &record.pk).await?;
			}
		}
		Ok(())
	}

	/// Runs all test suites against the given storage adaptor.
	pub async fn run_all<S: StorageAdaptor>(storage: &mut S) {
		// put tests
		test_put_insert(storage).await;
		test_put_upsert(storage).await;
		test_put_with_sort_key(storage).await;
		test_put_without_sort_key(storage).await;
		test_put_multiple_partitions(storage).await;

		// get tests
		test_get_existing(storage).await;
		test_get_after_update(storage).await;

		// delete tests
		test_delete_existing(storage).await;
		test_delete_nonexistent(storage).await;
		test_delete_idempotent(storage).await;

		// query tests
		test_query_empty_partition(storage).await;
		test_query_returns_partition_records(storage).await;
		test_query_ordering(storage).await;
		test_query_with_limit(storage).await;
		test_query_null_sort_key_ordering(storage).await;
		test_query_partition_isolation(storage).await;
		test_query_range(storage).await;

		// incremental_id tests
		test_incremental_id_starts_at_one(storage).await;
		test_incremental_id_increments(storage).await;
		test_incremental_id_partition_isolation(storage).await;
		test_incremental_id_persists_across_operations(storage).await;
	}

	/// Tests that put inserts a new record.
	pub async fn test_put_insert<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: "put_insert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"test data".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_insert_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.pk, b"put_insert_1");
		assert_eq!(retrieved.partition, 0);
		assert_eq!(retrieved.data, b"test data".to_vec());
	}

	/// Tests that put updates an existing record (upsert behavior).
	pub async fn test_put_upsert<S: StorageAdaptor>(storage: &mut S) {
		let record1 = Record {
			pk: b"put_upsert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"original".to_vec(),
		};
		storage.put(record1).await.expect("first put should succeed");

		let record2 = Record {
			pk: "put_upsert_1".into(),
			partition: 0,
			sort_key: None,
			data: b"updated".to_vec(),
		};
		storage
			.put(record2)
			.await
			.expect("second put should succeed");

		let retrieved = storage
			.get(0, b"put_upsert_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.data, b"updated".to_vec(), "data should be updated");
	}

	/// Tests that put correctly stores the sort key.
	pub async fn test_put_with_sort_key<S: StorageAdaptor>(storage: &mut S) {
		let sort_key = SortKey::u32_asc(42);
		let record = Record {
			pk: b"put_sort_key_1".into(),
			partition: 0,
			sort_key: Some(sort_key.clone()),
			data: b"with sort key".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_sort_key_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.sort_key, Some(sort_key));
	}

	/// Tests that put correctly handles records without sort keys.
	pub async fn test_put_without_sort_key<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"put_no_sort_key_1".into(),
			partition: 0,
			sort_key: None,
			data: b"no sort key".to_vec(),
		};

		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"put_no_sort_key_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert!(retrieved.sort_key.is_none());
	}

	/// Tests that put correctly handles multiple partitions.
	pub async fn test_put_multiple_partitions<S: StorageAdaptor>(storage: &mut S) {
		let record_a = Record {
			pk: "put_multi_a".into(),
			partition: 0,
			sort_key: None,
			data: b"in partition a".to_vec(),
		};
		let record_b = Record {
			pk: "put_multi_b".into(),
			partition: 1,
			sort_key: None,
			data: b"in partition b".to_vec(),
		};

		storage.put(record_a).await.expect("put a should succeed");
		storage.put(record_b).await.expect("put b should succeed");

		let retrieved_a = storage
			.get(0, b"put_multi_a")
			.await
			.expect("get should succeed")
			.expect("record a should exist");
		let retrieved_b = storage
			.get(1, b"put_multi_b")
			.await
			.expect("get should succeed")
			.expect("record b should exist");

		assert_eq!(retrieved_a.partition, 0);
		assert_eq!(retrieved_b.partition, 1);
	}

	/// Tests that get returns an existing record.
	pub async fn test_get_existing<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"get_existing_1".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(100)),
			data: b"test".to_vec(),
		};
		storage.put(record).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"get_existing_1")
			.await
			.expect("get should succeed");

		assert!(retrieved.is_some());
		let retrieved = retrieved.unwrap();
		assert_eq!(retrieved.pk, b"get_existing_1");
		assert_eq!(retrieved.partition, 0);
		assert_eq!(retrieved.data, b"test".to_vec());

		// superset of the key
		assert!(storage.get(0, b"get_existing_1_").await.unwrap().is_none());
		// subset of the key
		assert!(storage.get(0, b"get_existing_").await.unwrap().is_none());

		// non-existent key
		assert!(storage.get(0, b"get_nonexistent_does_not_exist").await.unwrap().is_none());
	}

	/// Tests that get returns updated data after put.
	pub async fn test_get_after_update<S: StorageAdaptor>(storage: &mut S) {
		let record1 = Record {
			pk: b"get_after_update_1".into(),
			partition: 0,
			sort_key: None,
			data: b"version1".to_vec(),
		};
		storage.put(record1).await.expect("put should succeed");

		let record2 = Record {
			pk: b"get_after_update_1".into(),
			partition: 0,
			sort_key: None,
			data: b"version2".to_vec(),
		};
		storage.put(record2).await.expect("put should succeed");

		let retrieved = storage
			.get(0, b"get_after_update_1")
			.await
			.expect("get should succeed")
			.expect("record should exist");

		assert_eq!(retrieved.data, b"version2".to_vec());
	}

	/// Tests that delete removes an existing record and returns it.
	pub async fn test_delete_existing<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"delete_existing_1".into(),
			partition: 0,
			sort_key: None,
			data: b"to delete".to_vec(),
		};
		storage.put(record.clone()).await.expect("put should succeed");

		let deleted_record = storage
			.delete(0, b"delete_existing_1")
			.await
			.expect("delete should succeed");

		assert_eq!(deleted_record, Some(record));

		let retrieved = storage
			.get(0, b"delete_existing_1")
			.await
			.expect("get should succeed");
		assert!(retrieved.is_none(), "record should no longer exist");
	}

	/// Tests that delete returns None for non-existent records.
	pub async fn test_delete_nonexistent<S: StorageAdaptor>(storage: &mut S) {
		let deleted_record = storage
			.delete(0, b"delete_nonexistent_does_not_exist")
			.await
			.expect("delete should succeed");

		assert!(
			deleted_record.is_none(),
			"delete should return None for non-existent record"
		);
	}

	/// Tests that delete is idempotent (second delete returns None).
	pub async fn test_delete_idempotent<S: StorageAdaptor>(storage: &mut S) {
		let record = Record {
			pk: b"delete_idempotent_1".into(),
			partition: 0,
			sort_key: None,
			data: b"delete twice".to_vec(),
		};
		storage.put(record.clone()).await.expect("put should succeed");

		let first_delete = storage
			.delete(0, b"delete_idempotent_1")
			.await
			.expect("first delete should succeed");
		let second_delete = storage
			.delete(0, b"delete_idempotent_1")
			.await
			.expect("second delete should succeed");

		assert_eq!(first_delete, Some(record), "first delete should return the record");
		assert_eq!(second_delete, None, "second delete should return None");
	}

	/// Tests that query returns empty results for empty partition.
	pub async fn test_query_empty_partition<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		let results = storage
			.query(Query::new(0))
			.await
			.expect("query should succeed");

		assert!(results.is_empty());
	}

	/// Tests that query returns all records in a partition.
	pub async fn test_query_returns_partition_records<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		for i in 0..3 {
			let record = Record {
				pk: format!("query_partition_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query(Query::new(0))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 3);
	}

	/// Tests that query returns records in ascending sort key order by default.
	pub async fn test_query_ordering<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		// Insert in non-sequential order
		for i in [5, 2, 8, 1, 9] {
			let record = Record {
				pk: format!("query_asc_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query(Query::new(0))
			.await
			.expect("query should succeed");

		let values = results.iter().map(|r| r.data.clone()).collect::<Vec<_>>();
		assert_eq!(
			values,
			vec![b"record_1".to_vec(), b"record_2".to_vec(), b"record_5".to_vec(), b"record_8".to_vec(), b"record_9".to_vec()],
			"should be in ascending order"
		);
	}

	/// Tests that query with limit returns at most N records.
	pub async fn test_query_with_limit<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		for i in 0..10 {
			let record = Record {
				pk: format!("query_limit_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results = storage
			.query(Query::new(0).limit(3))
			.await
			.expect("query should succeed");

		assert_eq!(results.len(), 3);
		let values = results.iter().map(|r| r.data.clone()).collect::<Vec<_>>();
		assert_eq!(
			values,
			vec![b"record_0".to_vec(), b"record_1".to_vec(), b"record_2".to_vec()],
			"should return first 3 records"
		);
	}

	/// Tests that records without sort keys are ordered last (or first when reversed).
	pub async fn test_query_null_sort_key_ordering<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();
		// Records with sort keys
		let with_key_1 = Record {
			pk: "query_null_with_1".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(1)),
			data: b"with_key_1".to_vec(),
		};
		let with_key_2 = Record {
			pk: "query_null_with_2".into(),
			partition: 0,
			sort_key: Some(SortKey::u32_asc(2)),
			data: b"with_key_2".to_vec(),
		};

		// Record without sort key
		let without_key = Record {
			pk: "query_null_without".into(),
			partition: 0,
			sort_key: None,
			data: b"no_key".to_vec(),
		};

		storage.put(with_key_1).await.expect("put should succeed");
		storage.put(without_key).await.expect("put should succeed");
		storage.put(with_key_2).await.expect("put should succeed");

		// Ascending: nulls last
		let results_asc = storage
			.query(Query::new(0))
			.await
			.expect("query should succeed");

		assert_eq!(results_asc.len(), 3);
		assert_eq!(results_asc[0].data, b"with_key_1".to_vec());
		assert_eq!(results_asc[1].data, b"with_key_2".to_vec());
		assert_eq!(results_asc[2].data, b"no_key".to_vec(), "null sort key should be last");
	}

	/// Tests that query only returns records from the specified partition.
	pub async fn test_query_partition_isolation<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1]).await.unwrap();
		// Records in partition A
		for i in 0..3 {
			let record = Record {
				pk: format!("query_iso_a_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Records in partition B
		for i in 0..5 {
			let record = Record {
				pk: format!("query_iso_b_{}", i).into(),
				partition: 1,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i + 100).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		let results_a = storage
			.query(Query::new(0))
			.await
			.expect("query should succeed");

		let results_b = storage
			.query(Query::new(1))
			.await
			.expect("query should succeed");

		assert_eq!(results_a.len(), 3, "partition A should have 3 records");
		assert_eq!(results_b.len(), 5, "partition B should have 5 records");

		// Verify all results_a are from partition A
		assert!(results_a
			.iter()
			.all(|r| r.partition == 0));

		// Verify all results_b are from partition B
		assert!(results_b
			.iter()
			.all(|r| r.partition == 1));
	}

	/// Tests that query with start and end keys returns only records within the range.
	pub async fn test_query_range<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0]).await.unwrap();

		// Insert records with sort keys 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
		for i in 1..=10u32 {
			let record = Record {
				pk: format!("query_range_{}", i).into(),
				partition: 0,
				sort_key: Some(SortKey::u32_asc(i)),
				data: format!("record_{}", i).as_bytes().to_vec(),
			};
			storage.put(record).await.expect("put should succeed");
		}

		// Query with start key only (>= 5)
		let results_start = storage
			.query(Query::new(0).start(SortKey::u32_asc(5)))
			.await
			.expect("query should succeed");

		assert_eq!(results_start.len(), 6, "should return records 5-10");
		let values: Vec<_> = results_start.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_5".to_vec(),
				b"record_6".to_vec(),
				b"record_7".to_vec(),
				b"record_8".to_vec(),
				b"record_9".to_vec(),
				b"record_10".to_vec(),
			],
			"should return records from 5 onwards"
		);

		// Query with end key only (<= 3)
		let results_end = storage
			.query(Query::new(0).end(SortKey::u32_asc(3)))
			.await
			.expect("query should succeed");

		assert_eq!(results_end.len(), 3, "should return records 1-3");
		let values: Vec<_> = results_end.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_1".to_vec(),
				b"record_2".to_vec(),
				b"record_3".to_vec(),
			],
			"should return records up to 3"
		);

		// Query with both start and end keys (3 <= x <= 7)
		let results_range = storage
			.query(Query::new(0).start(SortKey::u32_asc(3)).end(SortKey::u32_asc(7)))
			.await
			.expect("query should succeed");

		assert_eq!(results_range.len(), 5, "should return records 3-7");
		let values: Vec<_> = results_range.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_3".to_vec(),
				b"record_4".to_vec(),
				b"record_5".to_vec(),
				b"record_6".to_vec(),
				b"record_7".to_vec(),
			],
			"should return records in range 3-7"
		);

		// Query range with limit
		let results_range_limit = storage
			.query(Query::new(0).start(SortKey::u32_asc(2)).end(SortKey::u32_asc(8)).limit(3))
			.await
			.expect("query should succeed");

		assert_eq!(results_range_limit.len(), 3, "should return only 3 records due to limit");
		let values: Vec<_> = results_range_limit.iter().map(|r| r.data.clone()).collect();
		assert_eq!(
			values,
			vec![
				b"record_2".to_vec(),
				b"record_3".to_vec(),
				b"record_4".to_vec(),
			],
			"should return first 3 records in range"
		);

		// Query range that matches no records
		let results_empty = storage
			.query(Query::new(0).start(SortKey::u32_asc(100)).end(SortKey::u32_asc(200)))
			.await
			.expect("query should succeed");

		assert!(results_empty.is_empty(), "should return no records for out-of-range query");
	}

	/// Tests that incremental_id returns 1 for the first call on a partition.
	pub async fn test_incremental_id_starts_at_one<S: StorageAdaptor>(storage: &mut S) {
		// Clear the LAST_IDS entry for partition 0
		storage.delete(LAST_IDS, b"0").await.unwrap();
		let id = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		assert_eq!(id, 1, "first id should be 1");
	}

	/// Tests that incremental_id increments on subsequent calls.
	pub async fn test_incremental_id_increments<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, LAST_IDS]).await.unwrap();

		let id1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id3 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		assert_eq!(id1, 1, "first id should be 1");
		assert_eq!(id2, 2, "second id should be 2");
		assert_eq!(id3, 3, "third id should be 3");
	}

	/// Tests that incremental_id maintains separate sequences for different partitions.
	pub async fn test_incremental_id_partition_isolation<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1, LAST_IDS]).await.unwrap();

		// Generate IDs for partition A
		let a1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let a2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let a3 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");

		// Generate IDs for partition B
		let b1 = storage.incremental_id(1).await
			.expect("incremental_id should succeed");
		let b2 = storage.incremental_id(1).await
			.expect("incremental_id should succeed");

		// Partition A should have 1, 2, 3
		assert_eq!(a1, 1);
		assert_eq!(a2, 2);
		assert_eq!(a3, 3);

		// Partition B should have its own sequence starting at 1
		assert_eq!(b1, 1);
		assert_eq!(b2, 2);

		// Generate more for A - should continue from 3
		let a4 = storage.incremental_id(0).await.expect("incremental_id should succeed");
		assert_eq!(a4, 4);
	}

	/// Tests that incremental_id persists its state correctly.
	pub async fn test_incremental_id_persists_across_operations<S: StorageAdaptor>(storage: &mut S) {
		clear_partitions(storage, &[0, 1, LAST_IDS]).await.unwrap();

		// Generate some IDs
		let id1 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		let id2 = storage.incremental_id(0).await
			.expect("incremental_id should succeed");
		assert_eq!(id1, 1);
		assert_eq!(id2, 2);

		// Verify the stored value can be retrieved directly
		let stored = storage
			.get(LAST_IDS, &[0])
			.await
			.expect("get should succeed")
			.expect("id record should exist");
		let stored_id: u32 = serde_json::from_slice(&stored.data).expect("should deserialize");
		assert_eq!(stored_id, 2, "stored id should be 2");

		// Continue generating - should pick up where we left off
		let id3 = storage.incremental_id(0).await.expect("incremental_id should succeed");
		assert_eq!(id3, 3);
	}
}
