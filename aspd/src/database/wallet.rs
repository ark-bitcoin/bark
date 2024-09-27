//!
//! This module is responsible for storing the BDK wallet state to our db.
//!
//! The design is optimized for fast writes while running and trading off
//! startup performance.
//!
//! BDK defines a `ChangeSet` that is created when the wallet syncs or when
//! new transactions are made. `ChangeSet`s can be merged together.
//! On startup of the BDK wallet (which will not happen often for arkd),
//! an aggregated `ChangeSet` has to be provided.
//!
//! As such, we will store all `ChangeSet`s as in the tree, keyed by an
//! incrementing index, which we will store in memory.
//!


use std::sync::Arc;

use anyhow::{ensure, Context};
use bdk_wallet::{chain::Merge, ChangeSet};
use rocksdb::{BoundColumnFamily, FlushOptions, IteratorMode};
use tokio::sync::Mutex;

use super::RocksDb;

/// mapping from incrementing index to serialized [ChangeSet].
pub const CF_BDK_CHANGESETS: &str = "bdk_changesets";


pub struct ChangeSetDbState {
	/// The total number of [ChangeSet]s stored in the DB.
	count: Mutex<Option<u32>>,
}

impl ChangeSetDbState {
	pub fn new() -> Self {
		Self {
			count: Mutex::new(None),
		}
	}

	fn cf_changesets<'a>(&self, db: &'a RocksDb) -> Arc<BoundColumnFamily<'a>> {
		db.cf_handle(CF_BDK_CHANGESETS).expect("db missing bdk changesets cf")
	}

	pub async fn store_changeset(&self, db: &RocksDb, c: &ChangeSet) -> anyhow::Result<()> {
		let mut buf = Vec::new();
		ciborium::into_writer(c, &mut buf).unwrap();

		let mut lock = self.count.lock().await;
		let idx = lock.expect("can't store changeset without first reading the changesets");
		let key = idx.to_be_bytes();

		db.put_cf(&self.cf_changesets(db), key, buf)?;

		let mut opts = FlushOptions::default();
		opts.set_wait(true); //TODO(stevenroose) is this needed?
		db.flush_cfs_opt(&[&self.cf_changesets(db)], &opts).context("error flushing db")?;

		*lock = Some(idx + 1);
		Ok(())
	}

	pub async fn read_aggregate_changeset(&self, db: &RocksDb) -> anyhow::Result<Option<ChangeSet>> {
		let mut lock = self.count.lock().await;
		let mut ret = Option::<ChangeSet>::None;

		let iterator = db.iterator_cf(&self.cf_changesets(db), IteratorMode::Start);
		let mut cursor = 0;
		for res in iterator {
			let (key, value) = res.context("iterator broke")?;
			ensure!(key.len() == 4, "corrupt db");
			let idx = u32::from_be_bytes([key[0], key[1], key[2], key[3]]);
			ensure!(idx == cursor, "change set keys out of order, expected {}", cursor);
			cursor += 1;

			let cs = ciborium::from_reader::<ChangeSet, _>(&*value).context("corrupt db: changeset value")?;

			if let Some(ref mut r) = ret {
				r.merge(cs);
			} else {
				ret = Some(cs);
			}
		}

		*lock = Some(cursor);
		Ok(ret)
	}
}

impl super::Db {
	/// Store the new [ChangeSet] in the database.
	pub async fn store_changeset(&self, c: &ChangeSet) -> anyhow::Result<()> {
		self.wallet.store_changeset(&self.db, c).await
	}

	/// Read all the [ChangeSet]s and return their aggregate.
	pub async fn read_aggregate_changeset(&self) -> anyhow::Result<Option<ChangeSet>> {
		self.wallet.read_aggregate_changeset(&self.db).await
	}
}
