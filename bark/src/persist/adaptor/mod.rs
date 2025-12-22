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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
