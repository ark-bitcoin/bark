
use bitcoin::Amount;
use chrono::{DateTime, Local};

use crate::vtxo::VtxoStateKind;


/// Opaque sort key encoded as bytes for lexicographic comparison.
///
/// The encoding ensures that database-level `ORDER BY sort_key ASC` produces
/// the correct logical ordering. Use [`SortKeyBuilder`] to construct composite
/// keys with mixed ascending/descending fields.
///
/// # Database Storage
///
/// Store as `BLOB` (SQLite), `BYTEA` (Postgres), or raw bytes in NoSQL stores.
/// Create an index on `(partition, sort_key)` for efficient range scans.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SortKey(Vec<u8>);

impl SortKey {
	/// Returns the raw bytes for database storage.
	pub fn as_bytes(&self) -> &[u8] {
		&self.0
	}

	/// Constructs a sort key from raw bytes (for database retrieval).
	pub fn from_bytes(bytes: Vec<u8>) -> Self {
		Self(bytes)
	}

	/// Creates a builder for composite sort keys.
	pub fn builder() -> SortKeyBuilder {
		SortKeyBuilder(Vec::new())
	}

	/// Creates a sort key from a single u32, ascending order.
	pub fn u32_asc(n: u32) -> Self {
		Self::builder().u32_asc(n).build()
	}

	/// Creates a sort key from a single u64, descending order.
	pub fn u64_desc(n: u64) -> Self {
		Self::builder().u64_desc(n).build()
	}
}

/// Builder for constructing composite sort keys with multiple fields.
///
/// # Example
///
/// ```rust
/// # use bark::persist::adaptor::SortKey;
///
/// let height = 100;
/// let amount = 1000;
///
/// // Sort by height ascending, then amount descending
/// let key = SortKey::builder()
///     .u32_asc(height)
///     .u64_desc(amount)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub struct SortKeyBuilder(Vec<u8>);

impl SortKeyBuilder {
	pub fn u8_asc(mut self, n: u8) -> Self {
		self.0.push(n);
		self
	}

	/// Appends a u64 in ascending order.
	pub fn u32_asc(mut self, n: u32) -> Self {
		self.0.extend_from_slice(&n.to_be_bytes());
		self
	}

	/// Appends a u64 in descending order.
	pub fn u64_desc(mut self, n: u64) -> Self {
		self.0.extend_from_slice(&(!n).to_be_bytes());
		self
	}

	/// Builds the final sort key.
	pub fn build(self) -> SortKey {
		SortKey(self.0)
	}
}

pub(crate) fn vtxo_sort_key(vtxo_state: VtxoStateKind, expiry_height: u32, amount: Amount) -> SortKey {
	// Sort by state ASC, then expiry_height ASC, then amount DESC
	// This prioritizes VTXOs that expire sooner and are larger
	SortKey::builder()
		.u8_asc(vtxo_state.as_byte())
		.u32_asc(expiry_height)
		.u64_desc(amount.to_sat())
		.build()
}

pub(crate) fn movement_sort_key(created_at: &DateTime<Local>) -> SortKey {
	// Sort by created_at DESC (most recent first)
	SortKey::u64_desc(created_at.timestamp_millis() as u64)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sort_key_u64() {
		let k1 = SortKey::builder().u32_asc(1).build();
		let k2 = SortKey::builder().u32_asc(2).build();
		let k3 = SortKey::builder().u32_asc(3).build();

		assert!(k1 < k2);
		assert!(k2 < k3);
		assert!(k1 < k3);
	}

	#[test]
	fn sort_key_u64_desc() {
		let k1 = SortKey::builder().u64_desc(1).build();
		let k2 = SortKey::builder().u64_desc(2).build();
		let k3 = SortKey::builder().u64_desc(3).build();

		assert!(k1 > k2);
		assert!(k2 > k3);
		assert!(k1 > k3);
	}

	#[test]
	fn sort_key_composite() {
		// Sort by height ASC, then amount DESC
		let make_key = |height: u32, amount: u64| {
			SortKey::builder()
				.u32_asc(height)
				.u64_desc(amount)
				.build()
		};

		// Same height, higher amount should come first
		let k1 = make_key(100, 1000);
		let k2 = make_key(100, 500);
		assert!(k1 < k2); // 1000 DESC < 500 DESC

		// Lower height comes first regardless of amount
		let k3 = make_key(50, 100);
		assert!(k3 < k1);
		assert!(k3 < k2);

		// Higher height comes first regardless of amount
		let k4 = make_key(150, 100);
		assert!(k4 > k1);
		assert!(k4 > k2);
		assert!(k4 > k3);
	}
}
