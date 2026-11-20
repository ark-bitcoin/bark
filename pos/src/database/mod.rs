//! The posd database.

mod migrations {
	include!(concat!(env!("OUT_DIR"), "/migrations.rs"));
}

use std::fmt;
use std::str::FromStr;

use anyhow::Context;
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use chrono::{DateTime, Utc};
use postgres_types::{FromSql, ToSql};
use serde::{Deserialize, Serialize};
use tokio_postgres::{NoTls, Row};

use crate::config;


pub type PgPool = Pool<PostgresConnectionManager<NoTls>>;

#[derive(Clone)]
pub struct Db {
	pool: PgPool,
}

pub async fn pool(cfg: &config::Postgres) -> anyhow::Result<PgPool> {
	let manager = PostgresConnectionManager::new(cfg.to_pg_config(), NoTls);
	Pool::builder().max_size(cfg.max_connections).build(manager).await
		.with_context(|| format!("failed to connect to Postgres database {}", cfg.name))
}

impl Db {
	/// Connects and runs the migrations.
	pub async fn connect(cfg: &config::Postgres) -> anyhow::Result<Db> {
		let pool = pool(cfg).await?;
		let mut conn = pool.dedicated_connection().await?;
		migrations::runner().run_async(&mut conn).await.context("database migration failed")?;
		Ok(Db { pool })
	}

	pub async fn conn(&self) -> anyhow::Result<PooledConnection<'_, PostgresConnectionManager<NoTls>>> {
		Ok(self.pool.get().await?)
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSql, FromSql)]
#[postgres(name = "sale_state")]
#[serde(rename_all = "kebab-case")]
pub enum SaleState {
	#[postgres(name = "open")]
	Open,
	#[postgres(name = "in-progress")]
	InProgress,
	#[postgres(name = "paid")]
	Paid,
	#[postgres(name = "expired")]
	Expired,
	#[postgres(name = "canceled")]
	Canceled,
}

impl SaleState {
	pub fn as_str(&self) -> &'static str {
		match self {
			SaleState::Open => "open",
			SaleState::InProgress => "in-progress",
			SaleState::Paid => "paid",
			SaleState::Expired => "expired",
			SaleState::Canceled => "canceled",
		}
	}

	/// Whether the state can still change through a payment.
	pub fn is_live(&self) -> bool {
		matches!(self, SaleState::Open | SaleState::InProgress)
	}
}

impl fmt::Display for SaleState {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(self.as_str())
	}
}

impl FromStr for SaleState {
	type Err = anyhow::Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		Ok(match s {
			"open" => SaleState::Open,
			"in-progress" => SaleState::InProgress,
			"paid" => SaleState::Paid,
			"expired" => SaleState::Expired,
			"canceled" => SaleState::Canceled,
			_ => anyhow::bail!("unknown sale state: {}", s),
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSql, FromSql)]
#[postgres(name = "payment_rail")]
#[serde(rename_all = "kebab-case")]
pub enum Rail {
	#[postgres(name = "lightning")]
	Lightning,
	#[postgres(name = "ark")]
	Ark,
	#[postgres(name = "onchain")]
	Onchain,
}

impl Rail {
	pub fn as_str(&self) -> &'static str {
		match self {
			Rail::Lightning => "lightning",
			Rail::Ark => "ark",
			Rail::Onchain => "onchain",
		}
	}
}

#[derive(Debug, Clone)]
pub struct Store {
	pub id: i64,
	pub name: String,
	pub ark_address: String,
	pub claim_pubkey: String,
	pub mailbox_id: String,
	pub onchain_descriptor: String,
	pub currency: String,
	pub onchain_min_sat: i64,
	pub lightning_address_name: Option<String>,
}

pub const STORE_COLUMNS: &str = "s.id, s.name, s.ark_address, s.claim_pubkey, s.mailbox_id, \
	s.onchain_descriptor, s.currency, s.onchain_min_sat, s.lightning_address_name";

impl Store {
	pub fn from_row(row: &Row) -> Store {
		Store {
			id: row.get("id"),
			name: row.get("name"),
			ark_address: row.get("ark_address"),
			claim_pubkey: row.get("claim_pubkey"),
			mailbox_id: row.get("mailbox_id"),
			onchain_descriptor: row.get("onchain_descriptor"),
			currency: row.get("currency"),
			onchain_min_sat: row.get("onchain_min_sat"),
			lightning_address_name: row.get("lightning_address_name"),
		}
	}
}

#[derive(Debug, Clone)]
pub struct Device {
	pub id: i64,
	pub store_id: i64,
	pub name: String,
	pub created_at: DateTime<Utc>,
	pub revoked_at: Option<DateTime<Utc>>,
}

impl Device {
	pub fn from_row(row: &Row) -> Device {
		Device {
			id: row.get("id"),
			store_id: row.get("store_id"),
			name: row.get("name"),
			created_at: row.get("created_at"),
			revoked_at: row.get("revoked_at"),
		}
	}
}

/// A sale, with the payment details of its rails.
#[derive(Debug, Clone)]
pub struct Sale {
	pub id: i64,
	pub public_id: String,
	pub store_id: i64,
	pub device_name: Option<String>,
	pub amount_sat: i64,
	pub fiat_amount: Option<String>,
	pub currency: Option<String>,
	pub btc_price: Option<String>,
	pub memo: Option<String>,
	pub state: SaleState,
	pub paid_rail: Option<Rail>,
	pub received_sat: i64,
	pub created_at: DateTime<Utc>,
	pub expires_at: DateTime<Utc>,
	pub paid_at: Option<DateTime<Utc>>,
	pub lightning_invoice: Option<String>,
	pub ark_invoice: Option<String>,
	pub onchain_address: Option<String>,
}

/// Selects a sale joined with its device and its rails. Callers add the
/// WHERE clause.
pub const SALE_SELECT: &str = "
	SELECT s.id, s.public_id, s.store_id, d.name AS device_name, s.amount_sat, s.fiat_amount,
		s.currency, s.btc_price, s.memo, s.state, s.paid_rail, s.received_sat, s.created_at,
		s.expires_at, s.paid_at, ln.invoice AS lightning_invoice, ark.invoice AS ark_invoice,
		oc.onchain_address
	FROM sale s
	LEFT JOIN device d ON d.id = s.device_id
	LEFT JOIN sale_payment ln ON ln.sale_id = s.id AND ln.rail = 'lightning'
	LEFT JOIN sale_payment ark ON ark.sale_id = s.id AND ark.rail = 'ark'
	LEFT JOIN sale_payment oc ON oc.sale_id = s.id AND oc.rail = 'onchain'
";

impl Sale {
	pub fn from_row(row: &Row) -> Sale {
		Sale {
			id: row.get("id"),
			public_id: row.get("public_id"),
			store_id: row.get("store_id"),
			device_name: row.get("device_name"),
			amount_sat: row.get("amount_sat"),
			fiat_amount: row.get("fiat_amount"),
			currency: row.get("currency"),
			btc_price: row.get("btc_price"),
			memo: row.get("memo"),
			state: row.get("state"),
			paid_rail: row.get("paid_rail"),
			received_sat: row.get("received_sat"),
			created_at: row.get("created_at"),
			expires_at: row.get("expires_at"),
			paid_at: row.get("paid_at"),
			lightning_invoice: row.get("lightning_invoice"),
			ark_invoice: row.get("ark_invoice"),
			onchain_address: row.get("onchain_address"),
		}
	}
}

/// A payment rail of a sale that the watcher checks.
#[derive(Debug, Clone)]
pub struct WatchedPayment {
	pub payment_id: i64,
	pub sale_id: i64,
	pub sale_public_id: String,
	pub sale_state: SaleState,
	pub sale_amount_sat: i64,
	pub sale_expires_at: DateTime<Utc>,
	pub rail: Rail,
	pub payment_hash: Option<String>,
	pub onchain_address: Option<String>,
	pub received_sat: i64,
	pub pending_sat: i64,
	pub settled: bool,
	pub claim_pubkey: String,
	pub mailbox_id: String,
}

impl WatchedPayment {
	pub fn from_row(row: &Row) -> WatchedPayment {
		WatchedPayment {
			payment_id: row.get("payment_id"),
			sale_id: row.get("sale_id"),
			sale_public_id: row.get("public_id"),
			sale_state: row.get("state"),
			sale_amount_sat: row.get("amount_sat"),
			sale_expires_at: row.get("expires_at"),
			rail: row.get("rail"),
			payment_hash: row.get("payment_hash"),
			onchain_address: row.get("onchain_address"),
			received_sat: row.get("received_sat"),
			pending_sat: row.get("pending_sat"),
			settled: row.get::<_, Option<DateTime<Utc>>>("settled_at").is_some(),
			claim_pubkey: row.get("claim_pubkey"),
			mailbox_id: row.get("mailbox_id"),
		}
	}
}
