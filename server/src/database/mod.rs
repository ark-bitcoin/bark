
mod embedded {
	use refinery::embed_migrations;
	embed_migrations!("src/database/migrations");
}

pub mod block;
pub mod intman;
pub mod ln;
pub mod oor;
pub mod rounds;
pub mod vtxopool;

mod model;
mod query;

pub use self::block::BlockTable;
pub use self::model::*;


use std::borrow::Borrow;
use std::task;
use std::backtrace::Backtrace;
use std::collections::HashMap;
use std::pin::Pin;
use std::time::Duration;

use anyhow::Context;
use bb8::{ManageConnection, Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use bdk_wallet::{chain::Merge, ChangeSet};
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::{serialize, deserialize};
use bitcoin::secp256k1::{self, PublicKey};
use chrono::Local;
use futures::Stream;
use tokio_postgres::{Client, NoTls, GenericClient, RowStream};
use tokio_postgres::types::Type;
use tracing::{info, warn};
use ark::{ServerVtxo, ServerVtxoPolicy, Vtxo, VtxoId};
use ark::mailbox::MailboxIdentifier;
use ark::encode::ProtocolEncoding;

use crate::wallet::WalletKind;
use crate::config::Postgres as PostgresConfig;
use crate::telemetry;
use crate::telemetry::MailboxType;

/// Can be used as function argument when there are no query_raw arguments
const NOARG: &[&bool] = &[];

const DEFAULT_DATABASE: &str = "postgres";

/// A stored bitcoin tx with txid pre-calculated
pub struct StoredBitcoinTx {
	pub txid: Txid,
	pub tx: Transaction,
}

#[derive(Clone)]
pub struct Db {
	pool: Pool<PostgresConnectionManager<NoTls>>
}

impl Db {
	async fn run_migrations(&self) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await?;
		embedded::migrations::runner().run_async::<Client>(&mut conn).await?;
		info!("All migrations got successfully run");
		Ok(())
	}

	pub fn config(database: &str, config: &PostgresConfig) -> tokio_postgres::Config {
		let mut pg_config = tokio_postgres::Config::new();
		pg_config.host(&config.host);
		pg_config.port(config.port);
		pg_config.dbname(database);
		if let Some(user) = &config.user {
			pg_config.user(user);
		}
		if let Some(password) = &config.password {
			pg_config.password(password.leak_ref());
		}

		pg_config
	}

	async fn raw_connect(postgres_config: &PostgresConfig) -> anyhow::Result<Client> {
		let config = Self::config(&postgres_config.name, postgres_config);
		let (client, connection) = config.connect(NoTls).await?;

		tokio::spawn(async move {
			if let Err(e) = connection.await {
				panic!("postgres daemon connection error: {}", e);
			}
		});

		Ok(client)
	}

	async fn pool_connect(
		database: &str,
		postgres_config: &PostgresConfig,
	) -> anyhow::Result<Pool<PostgresConnectionManager<NoTls>>> {
		let config = Self::config(database, postgres_config);

		let manager = PostgresConnectionManager::new(config, NoTls);
		Ok(Pool::builder()
			.max_size(postgres_config.max_connections)
			.error_sink(Box::new(PoolErrorSink))
			.build(manager).await?)
	}

	async fn check_database_emptiness(conn: &Client) -> anyhow::Result<()> {
		let statement = conn.prepare("
			SELECT COUNT(*)
			FROM pg_catalog.pg_tables
			WHERE schemaname NOT IN ('pg_catalog', 'information_schema');
		").await?;

		if conn.query_one(&statement, &[]).await?.get::<_, i64>(0) > 0 {
			bail!("Database must be empty to create an Ark Server in it.")
		}

		Ok(())
	}

	pub async fn connect(config: &PostgresConfig) -> anyhow::Result<Self> {
		let pool = Self::pool_connect(&config.name, config).await?;

		let db = Db { pool };
		db.run_migrations().await?;

		Ok(db)
	}

	pub async fn create(config: &PostgresConfig) -> anyhow::Result<Self> {
		info!("Checking if a database exists...");
		let connect = Self::raw_connect(config).await;

		if let Ok(conn) = connect {
			info!("A database already exists for the server, checking if it is empty.");
			Self::check_database_emptiness(&conn).await?;
		} else {
			info!("No database set up yet, creating a new one.");
			let pool = Self::pool_connect(DEFAULT_DATABASE, config).await?;
			let conn= pool.get().await?;

			let statement = conn.prepare(
				&format!("CREATE DATABASE \"{}\"", config.name)
			).await?;
			conn.execute(&statement, &[]).await?;
		}

		Self::connect(config).await
	}

	pub async fn get_conn(&self) -> anyhow::Result<PooledConnection<'_, PostgresConnectionManager<NoTls>>> {
		telemetry::set_postgres_connection_pool_metrics(self.pool.state());
		match self.pool.get().await {
			Ok(conn) => {
				Ok(conn)
			},
			Err(e) => {
				slog!(PostgresConnectionPoolConnectionFailure,
					err: e.to_string(),
					backtrace: Backtrace::capture().to_string(),
				);
				Err(e.into())
			}
		}
	}

	/**
	 * VTXOs
	*/



	/// Atomically insert the given vtxos.
	///
	/// If one or more vtxo's is already present in the database
	/// the query will succeed.
	pub async fn upsert_vtxos<V: Borrow<ServerVtxo>>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		query::upsert_vtxos(&tx, vtxos).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn get_server_vtxo_by_id(
		&self,
		id: VtxoId,
	) -> anyhow::Result<VtxoState<ServerVtxoPolicy>> {
		let conn = self.get_conn().await?;
		query::get_vtxo_by_id(&*conn, id).await
	}

	pub async fn get_server_vtxos_by_id(
		&self,
		ids: &[VtxoId],
	) -> anyhow::Result<Vec<VtxoState<ServerVtxoPolicy>>> {
		let conn = self.get_conn().await?;
		query::get_vtxos_by_id(&*conn, ids).await
	}

	pub async fn get_user_vtxo_by_id(&self, id: VtxoId) -> anyhow::Result<VtxoState> {
		let v = self.get_server_vtxo_by_id(id).await?;
		match v.try_into_user_vtxo_state() {
			Ok(v) => Ok(v),
			Err(_) => bail!("requested VTXO {} is not a user VTXO", id),
		}
	}

	pub async fn get_user_vtxos_by_id(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>> {
		let vs = self.get_server_vtxos_by_id(ids).await?;
		Ok(vs.into_iter().map(|v| match v.try_into_user_vtxo_state() {
			Ok(v) => Ok(v),
			Err(v) => bail!("requested VTXO {} is not a user VTXO", v.vtxo_id),
		}).collect::<anyhow::Result<_, _>>()?)
	}


	/// Updates the virtual transaction tree.
	/// This method will
	/// - upsert new virtual transactions
	/// - upsert new vtxos
	/// - mark spends in the virtual transaction tree
	///
	/// This method will fail
	/// - if a database error occurred
	pub async fn update_virtual_transaction_tree<'a, V : Borrow<ServerVtxo>>(
		&self,
		new_virtual_txs: impl IntoIterator<Item = VirtualTransaction<'a>>,
		new_vtxos: impl IntoIterator<Item = V>,
		spend_info: impl IntoIterator<Item = (VtxoId, Txid)>,
	) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await.context("failed to connect to db")?;
		let tx = conn.transaction().await.context("failed to start db transaction")?;

		query::update_virtual_transaction_tree(&tx, new_virtual_txs, new_vtxos, spend_info).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn upsert_virtual_transaction(
		&self,
		txid: Txid,
		signed_tx: Option<&Transaction>,
		is_funding: bool,
		server_may_own_descendant_since: Option<chrono::DateTime<chrono::Local>>,
	) -> anyhow::Result<Txid> {
		let conn = self.get_conn().await?;
		let client = conn.client();
		query::upsert_virtual_transaction(client, txid, signed_tx, is_funding, server_may_own_descendant_since).await
	}

	/// Queries a virtual transaction by txid
	pub async fn get_virtual_transaction_by_txid(&self, txid: Txid) -> anyhow::Result<Option<VirtualTransaction<'static>>> {
		let conn = self.get_conn().await.context("Failed to connect to db")?;
		let client: &tokio_postgres::Client = conn.client();
		query::get_virtual_transaction_by_txid(client, txid).await
	}

	/// Returns the first txid that exists as an unsigned virtual transaction,
	/// or None if all txids are either signed or don't exist in the table.
	pub async fn get_first_unsigned_virtual_transaction(&self, txids: &[Txid]) -> anyhow::Result<Option<Txid>> {
		let conn = self.get_conn().await.context("Failed to connect to db")?;
		let client: &tokio_postgres::Client = conn.client();
		query::get_first_unsigned_virtual_transaction(client, txids).await
	}

	/// Marks virtual transactions as having server-owned descendants.
	///
	/// This function:
	/// 1. Fails if any of the txids have NULL signed_tx (returns the first offending txid)
	/// 2. Updates server_may_own_descendant_since only where it's currently NULL
	/// 3. Does not overwrite existing server_may_own_descendant_since values
	pub async fn mark_server_may_own_descendants(
		&self,
		txids: &[Txid],
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await.context("failed to connect to db")?;
		query::mark_server_may_own_descendants(&*conn, txids).await
	}

	/**
	 * Arkoors
	*/

	#[deprecated]
	pub async fn store_arkoor_by_vtxo_pubkey(
		&self,
		pubkey: PublicKey,
		arkoor_package_id: &[u8; 32],
		vtxo: Vtxo,
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			INSERT INTO arkoor_mailbox (pubkey, vtxo_id, vtxo, arkoor_package_id, created_at)
			SELECT $1, id, $2, $3, NOW()
			FROM vtxo
			WHERE vtxo_id = $4;
		").await?;
		let rows_affected = conn.execute(&statement, &[
			&pubkey.serialize().to_vec(),
			&ProtocolEncoding::serialize(&vtxo),
			&arkoor_package_id.to_vec(),
			&vtxo.id().to_string(),
		]).await?;
		debug_assert_eq!(rows_affected, 1);

		telemetry::add_to_mailbox(MailboxType::LegacyVtxo, 1);

		Ok(())
	}

	#[deprecated]
	pub async fn pull_oors(
		&self,
		pubkeys: &[PublicKey],
	) -> anyhow::Result<HashMap<[u8; 32], Vec<Vtxo>>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT vtxo, arkoor_package_id
			FROM arkoor_mailbox
			WHERE pubkey = ANY($1) AND processed_at IS NULL;
		").await?;

		let serialized_pubkeys = pubkeys.iter()
			.map(|pk| pk.serialize().to_vec())
			.collect::<Vec<_>>();
		let rows = conn.query(&statement, &[&serialized_pubkeys]).await?;

		let mut vtxos_by_package_id = HashMap::<_, Vec<_>>::new();
		for row in &rows {
			let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
			let package_id = row.get::<_, Vec<u8>>("arkoor_package_id")
				.try_into().expect("invalid arkoor package id");

			vtxos_by_package_id.entry(package_id).or_default().push(vtxo);
		}

		let statement = conn.prepare("
			UPDATE arkoor_mailbox SET processed_at = NOW()
			WHERE pubkey = ANY($1) AND processed_at IS NULL;
		").await?;
		let result = conn.execute(&statement, &[&serialized_pubkeys]).await?;
		assert_eq!(result, rows.len() as u64);

		telemetry::get_from_mailbox(MailboxType::LegacyVtxo, rows.len());

		Ok(vtxos_by_package_id)
	}

	pub async fn store_vtxos_in_mailbox(
		&self,
		mailbox_id: MailboxIdentifier,
		vtxos: &[Vtxo],
	) -> anyhow::Result<Option<Checkpoint>> {
		if vtxos.len() == 0 {
			return Ok(None);
		}

		let conn = self.get_conn().await?;
		let statement = conn.prepare("SELECT next_checkpoint();").await?;
		let checkpoint = conn.query_one(&statement, &[]).await?;
		let checkpoint = checkpoint.get::<_, i64>(0);

		let statement = conn.prepare("
			INSERT INTO vtxo_mailbox (unblinded_mailbox_id, vtxo_id, vtxo, checkpoint, created_at)
			VALUES ($1, $2, $3, $4, NOW());
		").await?;
		for vtxo in vtxos {
			let rows_updated = conn.execute(&statement, &[
				&mailbox_id.to_string(),
				&vtxo.id().to_string(),
				&ProtocolEncoding::serialize(vtxo).to_vec(),
				&checkpoint,
			]).await?;
			debug_assert_eq!(rows_updated, 1);
		}

		telemetry::add_to_mailbox(MailboxType::BlindedVtxo, vtxos.len());

		Ok(Some(u64::try_from(checkpoint)?))
	}

	pub async fn get_vtxos_mailbox(
		&self,
		mailbox_id: MailboxIdentifier,
		checkpoint: Checkpoint,
		limit: usize,
	) -> anyhow::Result<Vec<(Checkpoint, Vec<Vtxo>)>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare(&format!("
			SELECT vtxo_id, vtxo, checkpoint
			FROM vtxo_mailbox
			WHERE unblinded_mailbox_id = $1 AND checkpoint > $2
			ORDER BY checkpoint ASC
			LIMIT {limit};
		")).await?;

		let checkpoint = checkpoint as i64;
		let mailbox_id = mailbox_id.to_string();
		let rows = conn.query(&statement, &[&mailbox_id, &checkpoint]).await?;
		if rows.is_empty() {
			return Ok(vec![]);
		}

		let mut res = Vec::new();
		let mut vtxos = Vec::new();
		let mut last_checkpoint = 0;
		for row in &rows {
			let checkpoint = row.get::<_, i64>("checkpoint") as u64;
			if vtxos.len() == 0 {
				last_checkpoint = checkpoint;
			}

			if last_checkpoint != checkpoint {
				telemetry::get_from_mailbox(MailboxType::BlindedVtxo, vtxos.len());
				res.push((last_checkpoint, vtxos.clone()));
				vtxos.clear();
				last_checkpoint = checkpoint;
			}

			let vtxo = Vtxo::deserialize(row.get("vtxo"))?;
			debug_assert_eq!(vtxo.id().to_string(), row.get::<_, String>("vtxo_id"));
			vtxos.push(vtxo);
		}

		telemetry::get_from_mailbox(MailboxType::BlindedVtxo, vtxos.len());
		res.push((last_checkpoint, vtxos));

		Ok(res)
	}

	/**
	 * Sweeps
	*/

	/// Add the pending sweep tx.
	pub async fn store_pending_sweep(&self, txid: &Txid, tx: &Transaction) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare_typed("
			INSERT INTO sweep (txid, tx, created_at) VALUES ($1, $2, NOW());
		", &[Type::TEXT, Type::BYTEA]).await?;
		conn.execute(
			&statement,
			&[&txid.to_string(), &serialize(tx)]
		).await?;

		Ok(())
	}

	/// Confirm the pending sweep tx by txid.
	pub async fn confirm_pending_sweep(&self, txid: &Txid) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let statement = conn.prepare("
			UPDATE sweep SET confirmed_at = NOW() WHERE txid = $1 AND confirmed_at IS NULL;
		").await?;
		conn.execute(&statement, &[&txid.to_string()]).await?;

		Ok(())
	}

	/// Abandon the pending sweep tx by txid.
	pub async fn abandon_pending_sweep(&self, txid: &Txid) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;

		let statement = conn.prepare("
			UPDATE sweep SET abandoned_at = NOW() WHERE txid = $1 AND abandoned_at IS NULL;
		").await?;
		conn.execute(&statement, &[&txid.to_string()]).await?;

		Ok(())
	}

	/// Fetch all pending sweep txs.
	pub async fn fetch_pending_sweeps(&self) -> anyhow::Result<HashMap<Txid, Transaction>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT txid, tx
			FROM sweep
			WHERE confirmed_at IS NULL AND abandoned_at IS NULL
		").await?;

		let rows = conn.query(&statement, &[]).await?;

		let pending_sweeps = rows
			.into_iter()
			.map(|row| -> anyhow::Result<(Txid, Transaction)> {
				let sweep = Sweep::try_from(row).expect("corrupt db");
				Ok((sweep.txid, sweep.tx))
			})
			.collect::<Result<HashMap<Txid, Transaction>, _>>()?;

		Ok(pending_sweeps)
	}

	// *************
	// * OFFBOARDS *
	// *************

	/// Store the offboard (as unbroadcast) and mark VTXOs as spent
	pub async fn register_offboard(
		&self,
		input_vtxos: impl IntoIterator<Item = VtxoId>,
		offboard_tx: &Transaction,
	) -> anyhow::Result<()> {
		let offboard_txid = offboard_tx.compute_txid().to_string();
		let offboard_tx_bytes = bitcoin::consensus::serialize(offboard_tx);

		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		let stmt = tx.prepare_typed(
			"INSERT INTO offboards (txid, signed_tx, wallet_commit, created_at)
			VALUES ($1, $2, FALSE, NOW());",
			&[Type::TEXT, Type::BYTEA]).await?;
		tx.execute(&stmt, &[&offboard_txid, &offboard_tx_bytes]).await?;

		let stmt = tx.prepare_typed(
			"UPDATE vtxo SET offboarded_in = $2, updated_at = NOW()
			WHERE vtxo_id = $1 AND
				spent_in_round IS NULL AND oor_spent_txid IS NULL AND offboarded_in IS NULL;",
			&[Type::TEXT, Type::TEXT],
		).await?;
		for vtxo in input_vtxos {
			let rows_affected = tx.execute(&stmt, &[&vtxo.to_string(), &offboard_txid]).await?;
			if rows_affected == 0 {
				bail!("VTXO {} is already spent", vtxo);
			}
		}

		tx.commit().await?;
		Ok(())
	}

	pub async fn mark_offboard_committed(&self, offboard_txid: Txid) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed(
			"UPDATE offboards SET wallet_commit = TRUE WHERE txid = $1;",
			&[Type::TEXT],
		).await?;
		ensure!(conn.execute(&stmt, &[&offboard_txid.to_string()]).await? > 0,
			"no offboard with txid {}", offboard_txid,
		);
		Ok(())
	}

	pub async fn get_uncommitted_offboards(&self) -> anyhow::Result<Vec<StoredBitcoinTx>> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed(
			"SELECT txid, signed_tx FROM offboards WHERE wallet_commit IS FALSE;", &[],
		).await?;
		let rows = conn.query(&stmt, &[]).await?;
		let mut ret = Vec::with_capacity(rows.len());
		for row in rows {
			ret.push(StoredBitcoinTx {
				txid: row.get::<_, &str>("txid").parse().expect("corrupt db: invalid txid"),
				tx: deserialize(row.get("signed_tx")).expect("corrupt db: invalid tx"),
			});
		}
		Ok(ret)
	}

	pub async fn store_changeset(&self, wallet: WalletKind, c: &ChangeSet) -> anyhow::Result<()> {
		let bytes = rmp_serde::to_vec_named(c).expect("serde serialization");

		let conn = self.get_conn().await?;
		let statement = conn.prepare_typed("
			INSERT INTO wallet_changeset (content, kind, created_at)
			VALUES ($1, $2::TEXT::wallet_kind, NOW());
		", &[Type::BYTEA, Type::TEXT]).await?;
		conn.execute(&statement, &[&bytes, &wallet.name()]).await?;

		Ok(())
	}

	pub async fn read_aggregate_changeset(
		&self,
		wallet: WalletKind,
	) -> anyhow::Result<Option<ChangeSet>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT content
			FROM wallet_changeset
			WHERE kind = $1::TEXT::wallet_kind
			ORDER BY id ASC;
		").await?;
		let rows = conn.query(&statement, &[&wallet.name()]).await?;

		let mut ret = Option::<ChangeSet>::None;
		for row in rows {
			let value = row.get::<_, Vec<u8>>(0);
			let cs = rmp_serde::from_slice::<ChangeSet>(&*value)
				.context("corrupt db: changeset value")?;

			if let Some(ref mut r) = ret {
				r.merge(cs);
			} else {
				ret = Some(cs);
			}
		}

		Ok(ret)
	}

	// ***********
	// * TXINDEX *
	// ***********

	/// Adds a [bitcoin::Transaction] to the database
	/// that can be queried by [bitcoin::Txid].
	pub async fn upsert_bitcoin_transaction(
		&self,
		txid: Txid,
		tx: &Transaction
	) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare_typed(
			"INSERT INTO bitcoin_transaction
				(txid, tx, created_at)
			VALUES
				($1, $2, NOW())
			ON CONFLICT DO NOTHING"
			, &[Type::TEXT, Type::BYTEA]).await?;

		// Prepare the data

		conn.execute(
			&statement,
			&[&txid.to_string(), &serialize(&tx)]
		).await?;

		Ok(())
	}

	pub async fn get_bitcoin_transaction_by_id(
		&self,
		txid: Txid,
	) -> anyhow::Result<Option<Transaction>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare(
			"SELECT tx FROM bitcoin_transaction WHERE txid = $1",
		).await?;

		match conn.query_opt(&statement, &[&txid.to_string()]).await? {
			Some(row) => {
				let tx_bytes: &[u8] = row.get("tx");
				let tx = deserialize(tx_bytes)
					.expect("Corrupt transaction in database");
				Ok(Some(tx))
			},
			None => Ok(None)
		}
	}

	// ********************
	// * ephemeral tweaks *
	// ********************

	pub async fn store_ephemeral_tweak(
		&self,
		pubkey: PublicKey,
		tweak: secp256k1::Scalar,
		lifetime: Duration,
	) -> anyhow::Result<()> {
		if let Err(e) = self.clean_expired_ephemeral_tweaks().await {
			warn!("Error while trying to clean up expired ephemeral tweaks: {:#}", e);
		}

		let conn = self.get_conn().await?;

		let stmt = conn.prepare("
			INSERT INTO ephemeral_tweak (pubkey, tweak, created_at, expires_at)
			VALUES ($1, $2, NOW(), $3)
		").await?;

		let expires_at = Local::now() + lifetime;
		let _ = conn.execute(&stmt, &[
			&pubkey.to_string(),
			&&tweak.to_be_bytes()[..],
			&expires_at,
		]).await.context("inserting ephemeral tweak")?;

		slog!(StoredEphemeralTweak, pubkey, expires_at);
		Ok(())
	}

	pub async fn fetch_ephemeral_tweak(
		&self,
		pubkey: PublicKey,
	) -> anyhow::Result<Option<secp256k1::Scalar>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare(
			"SELECT tweak FROM ephemeral_tweak WHERE pubkey = $1 LIMIT 1",
		).await?;
		let res = conn.query_opt(&stmt, &[&pubkey.to_string()]).await
			.context("fetching ephemeral tweak")?;

		Ok(res.map(|row| {
			let bytes = <[u8; 32]>::try_from(row.get::<_, &[u8]>(0)).expect("corrupt db");
			let ret = secp256k1::Scalar::from_be_bytes(bytes).expect("stored previously");
			slog!(FetchedEphemeralTweak, pubkey);
			ret
		}))
	}

	pub async fn drop_ephemeral_tweak(
		&self,
		pubkey: PublicKey,
	) -> anyhow::Result<Option<secp256k1::Scalar>> {
		let conn = self.get_conn().await?;

		let stmt = conn.prepare(
			"DELETE FROM ephemeral_tweak WHERE pubkey = $1 RETURNING tweak",
		).await?;
		let res = conn.query_opt(&stmt, &[&pubkey.to_string()]).await
			.context("fetching ephemeral tweak")?;

		Ok(res.map(|row| {
			let bytes = <[u8; 32]>::try_from(row.get::<_, &[u8]>(0)).expect("corrupt db");
			let ret = secp256k1::Scalar::from_be_bytes(bytes).expect("stored previously");
			slog!(DroppedEphemeralTweak, pubkey);
			ret
		}))
	}

	pub async fn clean_expired_ephemeral_tweaks(&self) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare(
			"DELETE FROM ephemeral_tweak WHERE expires_at < NOW()",
		).await?;
		let nb_tweaks = conn.execute(&stmt, &[]).await.context("cleaning ephemeral tweaks")?;
		if nb_tweaks > 0 {
			slog!(CleanedEphemeralTweaks, nb_tweaks: nb_tweaks as usize);
		}
		Ok(())
	}
}

/// A wrapper around [RowStream] that bundles the connection along with it
#[pin_project::pin_project]
pub(crate) struct OwnedRowStream<'a, M: bb8::ManageConnection> {
	/// We carry this to keep the connection alive as long as the stream
	_conn: bb8::PooledConnection<'a, M>,
	#[pin]
	inner: RowStream,
}

impl<'a, M: bb8::ManageConnection> OwnedRowStream<'a, M> {
	fn new(
		conn: bb8::PooledConnection<'a, M>,
		row_stream: RowStream,
	) -> OwnedRowStream<'a, M> {
		OwnedRowStream {
			_conn: conn,
			inner: row_stream,
		}
	}
}

impl<'a, M> Stream for OwnedRowStream<'a, M>
where
	M: ManageConnection,
	<M as ManageConnection>::Connection: Unpin,
{
	type Item = <RowStream as Stream>::Item;

	fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Option<Self::Item>> {
		self.project().inner.as_mut().poll_next(cx)
	}
}

#[derive(Debug)]
struct PoolErrorSink;

impl bb8::ErrorSink<tokio_postgres::Error> for PoolErrorSink {
	fn sink(&self, error: tokio_postgres::Error) {
		slog!(PostgresPoolError,
			err: error.to_string(),
			code: error.code().map(|c| c.code().to_owned()),
		);
	}

	fn boxed_clone(&self) -> Box<dyn bb8::ErrorSink<tokio_postgres::Error>> {
		Box::new(PoolErrorSink)
	}
}

#[cfg(test)]
mod test {
	use std::str::FromStr;
	use std::sync::Arc;

	use bdk_wallet::chain::{keychain_txout, local_chain, tx_graph, ConfirmationBlockTime, DescriptorId};
	use bitcoin::{BlockHash, OutPoint, Transaction};
	use bitcoin::consensus::encode::deserialize_hex;
	use bitcoin::hashes::{sha256, Hash};
	use bitcoin::hashes::hex::DisplayHex;

	#[test]
	fn bdk_changeset_serialization_stability() {
		let block1 = BlockHash::from_str("36781cb353907ac940052d1c6a88d599e48ef7351307803a24899b4f672bb22b").unwrap();
		let block2 = BlockHash::from_str("9381aff9163f7ba4ae7504b4c95c0e3f8f5f99961db113d0dd57337127c23eb0").unwrap();
		let tx = deserialize_hex::<Transaction>("020000000001012c4d834818787a979ed1f35104baf1b6d3d78c290d95b11f6c9c1796ece37f930000000000fdffffff0280841e0000000000225120d2e18c25e0947343ef6b0bc11daea76302fcb1e0a97de340582453a003ccd523793f7c3b0000000022512097abba9f4e0f470cbbbef97bc68ca8abf488b67aa97ef394cc7347dd5e96fc0301405f5489f911968a6d4e2bc57477c8b7f2d6f977d75dc603358754ea27f86dad666cf1c443a33a7cec7bba477800f954ed0600b13fcad4aab5865f72ee83d9236a69000000").unwrap();
		let txid = tx.compute_txid();
		let xpub = "xpub661MyMwAqRbcGUSLHUTToGHgqHDy17ZFcDgHtF6X1unzY9bhz8VyHqfVFoJZeYmtUz7G86sTRLPa4BjQ6aAzE1UqfizPhxKcPtrxNSGgYh9";
		let conf = ConfirmationBlockTime {
			block_id: (101456, block1).into(),
			confirmation_time: 11_111_111,
		};
		let cs = bdk_wallet::ChangeSet {
			descriptor: Some(format!("tr({xpub}/0'/0/*)").parse().unwrap()),
			change_descriptor: Some(format!("tr({xpub}/0'/1/*)").parse().unwrap()),
			network: Some(bitcoin::Network::Bitcoin),
			local_chain: local_chain::ChangeSet {
				blocks: [
					(420, Some(block1)),
					(421, Some(block2)),
				].into_iter().collect(),
			},
			tx_graph: tx_graph::ChangeSet {
				txs: [Arc::new(tx.clone()), Arc::new(tx.clone())].into_iter().collect(),
				txouts: [
					(OutPoint::new(txid, 0), tx.output[0].clone()),
					(OutPoint::new(txid, 1), tx.output[1].clone()),
				].into_iter().collect(),
				anchors: [(conf.clone(), txid), (conf.clone(), txid)].into_iter().collect(),
				last_seen: [(txid, 11_111_112), (txid, 22_222_222)].into_iter().collect(),
				last_evicted: [(txid, 11_111_114), (txid, 22_222_224)].into_iter().collect(),
				first_seen: [(txid, 11_111_115), (txid, 22_222_225)].into_iter().collect(),
			},
			indexer: keychain_txout::ChangeSet {
				last_revealed: [
				].into_iter().collect(),
				spk_cache: [
					(DescriptorId(sha256::Hash::hash(&[0])), [
						(420, tx.output[0].script_pubkey.clone()),
						(421, tx.output[1].script_pubkey.clone()),
					].into_iter().collect()),
					(DescriptorId(sha256::Hash::hash(&[1])), [
						(430, tx.output[0].script_pubkey.clone()),
						(431, tx.output[1].script_pubkey.clone()),
					].into_iter().collect()),
				].into_iter().collect(),
			},
		};

		let encoded = rmp_serde::to_vec_named(&cs).unwrap();
		let decoded = rmp_serde::from_slice(&encoded).unwrap();
		assert_eq!(cs, decoded);
		let re_encoded = rmp_serde::to_vec_named(&decoded).unwrap();
		assert_eq!(encoded.as_hex().to_string(), re_encoded.as_hex().to_string());

		let stable = "86aa64657363726970746f72d983747228787075623636314d794d7741715262634755534c485554546f4748677148447931375a46634467487446365831756e7a593962687a38567948716656466f4a5a65596d74557a374738367354524c506134426a513661417a4531557166697a5068784b63507472784e5347675968392f30272f302f2a2923713867333270336ab16368616e67655f64657363726970746f72d983747228787075623636314d794d7741715262634755534c485554546f4748677148447931375a46634467487446365831756e7a593962687a38567948716656466f4a5a65596d74557a374738367354524c506134426a513661417a4531557166697a5068784b63507472784e5347675968392f30272f312f2a2923336e647368357032a76e6574776f726ba7626974636f696eab6c6f63616c5f636861696e81a6626c6f636b7382cd01a4c4202bb22b674f9b89243a80071335f78ee499d5886a1c2d0540c97a9053b31c7836cd01a5c420b03ec227713357ddd013b11d96995f8f3f0e5cc9b40475aea47b3f16f9af8193a874785f677261706886a37478739184a776657273696f6e02a96c6f636b5f74696d6569a5696e7075749184af70726576696f75735f6f757470757482a474786964c4202c4d834818787a979ed1f35104baf1b6d3d78c290d95b11f6c9c1796ece37f93a4766f757400aa7363726970745f736967c400a873657175656e6365cefffffffda77769746e65737391dc00405f54cc89ccf911cc96cc8a6d4e2bccc57477ccc8ccb7ccf2ccd6ccf977ccd75dccc60335cc8754ccea27ccf86dccad666cccf1ccc443cca33a7cccec7bccba477800ccf954cced0600ccb13fcccaccd4ccaaccb5cc865f72cceecc83ccd9236aa66f75747075749282a576616c7565ce001e8480ad7363726970745f7075626b6579c4225120d2e18c25e0947343ef6b0bc11daea76302fcb1e0a97de340582453a003ccd52382a576616c7565ce3b7c3f79ad7363726970745f7075626b6579c422512097abba9f4e0f470cbbbef97bc68ca8abf488b67aa97ef394cc7347dd5e96fc03a674786f7574738282a474786964c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0a4766f75740082a576616c7565ce001e8480ad7363726970745f7075626b6579c4225120d2e18c25e0947343ef6b0bc11daea76302fcb1e0a97de340582453a003ccd52382a474786964c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0a4766f75740182a576616c7565ce3b7c3f79ad7363726970745f7075626b6579c422512097abba9f4e0f470cbbbef97bc68ca8abf488b67aa97ef394cc7347dd5e96fc03a7616e63686f7273919282a8626c6f636b5f696482a6686569676874ce00018c50a468617368c4202bb22b674f9b89243a80071335f78ee499d5886a1c2d0540c97a9053b31c7836b1636f6e6669726d6174696f6e5f74696d65ce00a98ac7c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0a96c6173745f7365656e81c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0ce0153158eac6c6173745f6576696374656481c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0ce01531590aa66697273745f7365656e81c420a7dec2bb3de2e38232180628c0a32ae87bba7f40afa639ed03090c9f57c5dcb0ce01531591a7696e646578657282ad6c6173745f72657665616c656480a973706b5f636163686582c4204bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a82cd01aec4225120d2e18c25e0947343ef6b0bc11daea76302fcb1e0a97de340582453a003ccd523cd01afc422512097abba9f4e0f470cbbbef97bc68ca8abf488b67aa97ef394cc7347dd5e96fc03c4206e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d82cd01a4c4225120d2e18c25e0947343ef6b0bc11daea76302fcb1e0a97de340582453a003ccd523cd01a5c422512097abba9f4e0f470cbbbef97bc68ca8abf488b67aa97ef394cc7347dd5e96fc03";
		assert_eq!(encoded.as_hex().to_string(), stable);
	}
}
