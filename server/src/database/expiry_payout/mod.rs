//! Expiry payouts: decide who owns each VTXO of an expired tree, guard
//! those decisions against other spends, and store the transactions that
//! pay the owners.

pub mod decision;
pub mod ownership;
pub mod payout;
pub(crate) mod guard;
mod allocation;

use crate::config::Postgres as PostgresConfig;
use crate::database::{Db, Tx};

impl Db {
	/// Create the database as [Db::create] does, in expiry payout mode if
	/// `expiry_payouts` is set. The mode is fixed for the life of the
	/// database, because each VTXO records its owner mailbox only in
	/// payout mode.
	pub async fn create_with_payouts(config: &PostgresConfig, expiry_payouts: bool) -> anyhow::Result<Db> {
		let mut db = Db::create(config).await?;
		if expiry_payouts {
			db.write(async |t| {
				t.execute("UPDATE server_mode SET expiry_payouts = TRUE", &[]).await?;
				Ok(())
			}).await?;
			db.expiry_payouts = true;
		}
		Ok(db)
	}

	/// Load the mode that was fixed when the database was created.
	pub(super) async fn load_expiry_payouts(&mut self) -> anyhow::Result<()> {
		self.expiry_payouts = self.read(async |t| {
			Ok(t.query_one("SELECT expiry_payouts FROM server_mode", &[]).await?.get("expiry_payouts"))
		}).await?;
		Ok(())
	}

	pub fn expiry_payouts(&self) -> bool {
		self.expiry_payouts
	}
}

impl Tx<'_> {
	pub fn expiry_payouts(&self) -> bool {
		self.expiry_payouts
	}
}
