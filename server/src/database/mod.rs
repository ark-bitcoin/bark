
mod embedded {
	use refinery::embed_migrations;
	embed_migrations!("src/database/migrations");
}
pub mod intman;

pub mod forfeits;
pub mod ln;
pub mod oor;
pub mod rounds;
pub mod vtxopool;

mod model;
mod query;

pub use model::*;


use std::task;
use std::backtrace::Backtrace;
use std::borrow::Borrow;
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
use futures::{Stream, TryStreamExt};
use tokio_postgres::{Client, NoTls, RowStream};
use tokio_postgres::types::Type;
use log::{info, warn};

use ark::{Vtxo, VtxoId, VtxoRequest};
use ark::mailbox::MailboxIdentifier;
use ark::arkoor::ArkoorPackageBuilder;
use ark::encode::ProtocolEncoding;
use ark::rounds::RoundId;
use bitcoin_ext::BlockHeight;

use crate::wallet::WalletKind;
use crate::config::Postgres as PostgresConfig;
use crate::telemetry;
use crate::telemetry::MailboxType;

/// Can be used as function argument when there are no query_raw arguments
const NOARG: &[&bool] = &[];

const DEFAULT_DATABASE: &str = "postgres";

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
	pub async fn upsert_vtxos<V: Borrow<Vtxo>>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		query::upsert_vtxos(&tx, vtxos).await?;

		tx.commit().await?;
		Ok(())
	}

	/// Upsert a board into the database
	pub async fn upsert_board(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;
		query::upsert_vtxos(&tx, [vtxo]).await?;
		query::upsert_board(&tx, vtxo.id(), vtxo.expiry_height()).await?;
		tx.commit().await?;
		Ok(())
	}

	/// Get all board are sweepable
	/// A board is sweepable if it has expired and the funding outpoint hasn't been spent yet
	/// A spent could be a sweep or an exit
	pub async fn get_sweepable_boards(
		&self,
		height: BlockHeight,
	) -> anyhow::Result<Vec<Board>> {
		let conn = self.get_conn().await?;
		query::get_sweepable_boards(&*conn, height).await
	}

	pub async fn mark_board_swept(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let conn = self.get_conn().await?;
		query::mark_board_swept(&*conn, vtxo.id()).await
			.context("Failed to mark board as swept")?;
		Ok(())
	}

	pub async fn get_vtxos_by_id(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>> {
		let conn = self.get_conn().await?;
		query::get_vtxos_by_id(&*conn, ids).await
	}

	/// Fetch all vtxos that have been forfeited.
	pub async fn fetch_all_forfeited_vtxos(
		&self,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<Vtxo>> + '_> {
		let conn = self.get_conn().await?;
		//TODO(stevenroose) this query is wrong
		let stmt = conn.prepare("
			SELECT vtxo FROM vtxo WHERE forfeit_state IS NOT NULL;
		").await?;

		let raw = conn.query_raw(&stmt, NOARG).await?;
		let stream = OwnedRowStream::new(conn, raw);

		Ok(stream.err_into().map_ok(
			|row| Vtxo::deserialize(row.get("vtxo")).expect("corrupt db: vtxo")
		))
	}

	pub async fn fetch_vtxos_forfeited_in(
		&self,
		rounds: &[RoundId],
	) -> anyhow::Result<Vec<VtxoState>> {
		let conn = self.get_conn().await?;
		let stmt = conn.prepare_typed("
			SELECT v.id, v.vtxo_id, v.vtxo, v.expiry, v.oor_spent_txid, v.forfeit_state, v.forfeit_round_id,
				v.created_at, v.updated_at
			FROM vtxo AS v
				JOIN round ON round.id = v.forfeit_round_id
			WHERE round.funding_txid = ANY($1);
		", &[Type::TEXT_ARRAY]).await?;

		let ids = rounds.iter().map(|id| id.to_string()).collect::<Vec<_>>();
		conn.query(&stmt, &[&ids]).await?.into_iter()
			.map(|row| VtxoState::try_from(row))
			.collect()
	}

	/// Upsert new vtxos and mark vtxos as spend
	///
	/// It is performed in a single function to ensure atomicity
	/// Note, that the spend_info might mark newly created vtxos as spend
	pub async fn upsert_vtxos_and_mark_spends<V : Borrow<Vtxo>>(
		&self,
		new_vtxos: impl Iterator<Item = V>,
		spend_info: impl Iterator<Item = (VtxoId, Txid)>,
	) -> anyhow::Result<()> {
		let (vtxos, txids) = spend_info.collect::<(Vec<_>, Vec<_>)>();

		let mut conn = self.get_conn().await.context("Failed to connect to db")?;
		let tx = conn.transaction().await.context("Failed to start db transaction")?;

		query::upsert_vtxos(&tx, new_vtxos).await?;
		oor::mark_package_spent(&tx, &vtxos, &txids).await?;

		tx.commit().await?;
		Ok(())
	}


	/// Returns [None] if all the ids were not previously marked as signed
	/// and are now correctly marked as such.
	/// Returns [Some] for the first vtxo that was already signed.
	///
	/// Also stores the new OOR vtxos atomically.
	pub async fn check_set_vtxo_oor_spent_package(
		&self,
		builder: &ArkoorPackageBuilder<'_, VtxoRequest>,
	) -> anyhow::Result<Option<VtxoId>> {
		let mut conn = self.get_conn().await?;
		let tx = conn.transaction().await?;

		let new_vtxos = builder.new_vtxos().into_iter().flatten().collect::<Vec<_>>();

		let statement = tx.prepare_typed("
			UPDATE vtxo SET oor_spent_txid = $2, updated_at = NOW()
			WHERE
				vtxo_id = $1 AND
				forfeit_state IS NULL AND
				oor_spent_txid IS NULL;
		", &[Type::TEXT, Type::TEXT]).await?;

		for input in builder.inputs() {
			let txid = builder.spending_tx(input.id())
				.expect("spending tx should be present").compute_txid();

			let rows_affected = tx.execute(&statement, &[&input.id().to_string(), &txid.to_string()]).await?;
			if rows_affected == 0 {
				return Ok(Some(input.id()));
			}
		}

		query::upsert_vtxos(&tx, new_vtxos).await?;

		tx.commit().await?;
		Ok(None)
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
			&vtxo.serialize(),
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
				&vtxo.serialize().to_vec(),
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
	) -> anyhow::Result<Vec<(Checkpoint, Vec<Vtxo>)>> {
		let conn = self.get_conn().await?;
		let statement = conn.prepare("
			SELECT vtxo_id, vtxo, checkpoint
			FROM vtxo_mailbox
			WHERE unblinded_mailbox_id = $1 AND checkpoint > $2
			ORDER BY checkpoint ASC;
		").await?;

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

	// **********
	// * WALLET *
	// **********

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
		slog!(PostgresPoolError, err: error.to_string(),
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
