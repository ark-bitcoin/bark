
pub mod model;

mod embedded {
	use refinery::embed_migrations;
	embed_migrations!("src/database/migrations");
}


use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};

use anyhow::Context;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use bdk_wallet::{chain::Merge, ChangeSet};
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::serialize;
use bitcoin::secp256k1::{schnorr, PublicKey, SecretKey};
use bitcoin_ext::BlockHeight;
use futures::{Stream, TryStreamExt, StreamExt};
use tokio_postgres::{types::Type, Client, GenericClient, NoTls};
use log::info;

use ark::{BoardVtxo, Vtxo, VtxoId};
use ark::rounds::RoundId;
use ark::tree::signed::CachedSignedVtxoTree;
use ark::util::{Decodable, Encodable};

use crate::wallet::WalletKind;
use crate::config::Postgres as PostgresConfig;
use self::model::{PendingSweep, StoredRound, VtxoState};

const DEFAULT_DATABASE: &str = "postgres";

#[derive(Clone)]
pub struct Db {
	pool: Pool<PostgresConnectionManager<NoTls>>
}

impl Db {
	async fn run_migrations(&self) -> anyhow::Result<()> {
		let mut conn = self.pool.get().await?;
		embedded::migrations::runner().run_async::<Client>(&mut conn).await?;
		info!("All migrations got successfully run");
		Ok(())
	}

	fn config(database: &str, config: &PostgresConfig) -> tokio_postgres::Config {
		let mut pg_config = tokio_postgres::Config::new();
		pg_config.host(&config.host);
		pg_config.port(config.port);
		pg_config.dbname(database);
		if let Some(user) = &config.user {
			pg_config.user(user);
		}
		if let Some(password) = &config.password {
			pg_config.password(password);
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

	async fn pool_connect(database: &str, postgres_config: &PostgresConfig) -> anyhow::Result<Pool<PostgresConnectionManager<NoTls>>> {
		let config = Self::config(database, postgres_config);

		let manager = PostgresConnectionManager::new(config, NoTls);
		Ok(Pool::builder().build(manager).await?)
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

	pub async fn connect(config: &PostgresConfig)  -> anyhow::Result<Self> {
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

	/**
	 * VTXOs
	*/

	async fn inner_upsert_vtxos<T, V: Borrow<Vtxo>>(
		client: &T,
		vtxos: impl IntoIterator<Item = V>,
	) -> Result<(), tokio_postgres::Error>
		where T: GenericClient
	{
		// Store all vtxos created in this round.
		let statement = client.prepare_typed("
			INSERT INTO vtxo (id, vtxo, expiry) VALUES (
				UNNEST($1), UNNEST($2), UNNEST($3))
			ON CONFLICT DO NOTHING
		", &[Type::TEXT_ARRAY, Type::BYTEA_ARRAY, Type::INT4_ARRAY]).await?;

		let vtxos = vtxos.into_iter();
		let mut ids = Vec::with_capacity(vtxos.size_hint().0);
		let mut data = Vec::with_capacity(vtxos.size_hint().0);
		let mut expiry = Vec::with_capacity(vtxos.size_hint().0);
		for vtxo in vtxos {
			let vtxo = vtxo.borrow();
			ids.push(vtxo.id().to_string());
			data.push(vtxo.encode());
			expiry.push(vtxo.spec().expiry_height as i32);
		}

		client.execute(
			&statement,
			&[&ids, &data, &expiry]
		).await?;

		Ok(())
	}


	/// Atomically insert the given vtxos.
	///
	/// If one or more vtxo's is already present in the database
	/// the query will succeed.
	pub async fn upsert_vtxos(&self, vtxos: &[Vtxo]) -> anyhow::Result<()> {
		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		Self::inner_upsert_vtxos(&tx, vtxos).await?;

		tx.commit().await?;
		Ok(())
	}

	/// Get all board vtxos that expired before or on `height`.
	pub async fn get_expired_boards(
		&self,
		height: BlockHeight,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<BoardVtxo>> + '_> {
		let conn = self.pool.get().await?;

		// TODO: maybe store kind in a column to filter board at the db level
		let statement = conn.prepare_typed("
			SELECT id, vtxo, expiry, oor_spent, forfeit_sigs, board_swept FROM vtxo \
			WHERE expiry <= $1 AND board_swept = false
		", &[Type::INT4]).await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;

		Ok(rows.filter_map(|row| async move {
			row
				.map(|row | VtxoState::try_from(row).expect("corrupt db").vtxo.into_board())
				.map_err(Into::into)
				.transpose()
		}).fuse())
	}

	pub async fn mark_board_swept(&self, vtxo: &BoardVtxo) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;

		let statement = conn.prepare("
			UPDATE vtxo SET board_swept = true WHERE id = $1;
		").await?;

		conn.execute(&statement, &[&vtxo.id().to_string()]).await?;

		Ok(())
	}

	async fn get_vtxos_by_id_with_client<T>(client: &T, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>>
		where T : GenericClient + Sized
	{
		let statement = client.prepare_typed("
			SELECT id, vtxo, expiry, oor_spent, forfeit_sigs, board_swept
			FROM vtxo
			WHERE id = any($1);
		", &[Type::TEXT_ARRAY]).await?;

		let id_str = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
		let rows = client.query(&statement, &[&id_str]).await
			.context("Query get_vtxos_by_id failed")?;

		// Parse all rows
		let vtxos = rows.into_iter()
			.map(|row| VtxoState::try_from(row))
			.collect::<Result<Vec<_>,_>>()
			.context("Failed to parse VtxoState from database")?;

		// Bail if one of the id's could not be found
		if vtxos.len() != ids.len() {
			let found_ids = vtxos.iter().map(|v| v.id).collect::<HashSet<_>>();

			for id in ids {
				if !found_ids.contains(id) {
					return Err(anyhow::anyhow!("vtxo {} does not exist", id))
						.context(*id);
				}
			}
		}

		Ok(vtxos)
	}

	pub async fn get_vtxos_by_id(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>> {
		let conn = self.pool.get().await?;
		Self::get_vtxos_by_id_with_client(&*conn, ids).await
	}

	/// Returns [None] if all the ids were not previously marked as signed
	/// and are now correctly marked as such.
	/// Returns [Some] for the first vtxo that was already signed.
	///
	/// Also stores the new OOR vtxos atomically.
	pub async fn check_set_vtxo_oor_spent(
		&self,
		spent_ids: &[VtxoId],
		spending_tx: Txid,
		new_vtxos: &[Vtxo],
	) -> anyhow::Result<Option<VtxoId>> {
		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		let statement = tx.prepare_typed("
			UPDATE vtxo SET oor_spent = $2 WHERE id = $1;
		", &[Type::TEXT, Type::BYTEA]).await?;

		let vtxos = Self::get_vtxos_by_id_with_client(&tx, spent_ids).await?;
		for vtxo_state in vtxos {
			if !vtxo_state.is_spendable() {
				return Ok(Some(vtxo_state.id));
			}

			tx.execute(&statement, &[&vtxo_state.id.to_string(), &serialize(&spending_tx)]).await?;
		}

		Self::inner_upsert_vtxos(&tx, new_vtxos).await?;

		tx.commit().await?;
		Ok(None)
	}

	/**
	 * Arkoors
	*/

	pub async fn store_oor(&self, pubkey: PublicKey, vtxo: Vtxo) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO arkoor_mailbox (id, pubkey, vtxo) VALUES ($1, $2, $3);
		").await?;
		conn.execute(
			&statement,
			&[&vtxo.id().to_string(), &pubkey.serialize().to_vec(), &vtxo.encode()]
		).await?;

		Ok(())
	}

	pub async fn pull_oors(&self, pubkey: PublicKey) -> anyhow::Result<Vec<Vtxo>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT vtxo FROM arkoor_mailbox WHERE pubkey = $1
		").await?;

		let rows = conn.query(&statement, &[&pubkey.serialize().to_vec()]).await?;
		let oors = rows
			.into_iter()
			.map(|row| -> anyhow::Result<Vtxo> { Ok(Vtxo::decode(row.get("vtxo"))?) })
			.collect::<Result<Vec<_>, _>>()?;

		let statement = conn.prepare("
			UPDATE arkoor_mailbox SET deleted_at = NOW() WHERE pubkey = $1;
		").await?;
		let result = conn.execute(&statement, &[&pubkey.serialize().to_vec()]).await?;
		assert_eq!(result, oors.len() as u64);

		Ok(oors)
	}

	/**
	 * Rounds
	*/

	pub async fn finish_round(
		&self,
		round_tx: &Transaction,
		vtxos: &CachedSignedVtxoTree,
		connector_key: &SecretKey,
		forfeit_vtxos: Vec<(VtxoId, Vec<schnorr::Signature>)>,
	) -> anyhow::Result<()> {
		let round_id = round_tx.compute_txid();

		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		// First, store the round itself.
		let statement = tx.prepare_typed("
			INSERT INTO round (id, tx, signed_tree, nb_input_vtxos, connector_key, expiry)
			VALUES ($1, $2, $3, $4, $5, $6);
		", &[Type::TEXT, Type::BYTEA, Type::BYTEA, Type::INT4, Type::BYTEA, Type::INT4]).await?;
		tx.execute(
			&statement,
			&[
				&round_id.to_string(),
				&serialize(&round_tx),
				&vtxos.spec.encode(),
				&(forfeit_vtxos.len() as i32),
				&connector_key.secret_bytes().to_vec(),
				&(vtxos.spec.spec.expiry_height as i32)
			]
		).await?;

		// Then mark inputs as forfeited.
		let statement = tx.prepare_typed("
			UPDATE vtxo SET forfeit_sigs = $2 WHERE id = $1 AND spendable = true;
		", &[Type::TEXT, Type::BYTEA_ARRAY]).await?;
		for (id, sigs) in forfeit_vtxos.into_iter() {
			let rows_affected = tx.execute(&statement, &[
				&id.to_string(),
				&sigs.into_iter().map(|s| s.serialize().to_vec()).collect::<Vec<_>>()
			]).await?;
			if rows_affected == 0 {
				bail!("tried to mark unspendable vtxo as forfeited: {}", id);
			}
		}

		// Finally insert new vtxos.
		Self::inner_upsert_vtxos(&tx, vtxos.all_vtxos()).await?;

		tx.commit().await?;
		Ok(())
	}

	pub async fn get_round(&self, id: RoundId) -> anyhow::Result<Option<StoredRound>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key FROM round WHERE id = $1;
		").await?;

		let rows = conn.query(&statement, &[&id.to_string()]).await?;
		let round = match rows.get(0) {
			Some(row) => Some(StoredRound::try_from(row.clone()).expect("corrupt db")),
			_ => None
		};

		Ok(round)
	}

	pub async fn remove_round(&self, id: RoundId) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;

		let statement = conn.prepare("
			UPDATE round SET deleted_at = NOW() WHERE id = $1;
		").await?;

		conn.execute(&statement, &[&id.to_string()]).await?;

		Ok(())
	}

	/// Get all round IDs of rounds that expired before or on `height`.
	pub async fn get_expired_rounds(&self, height: BlockHeight) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key FROM round WHERE expiry <= $1
		").await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;
		Ok(rows.map_ok(|row| StoredRound::try_from(row).expect("corrupt db").id).try_collect::<Vec<_>>().await?)
	}

	pub async fn get_fresh_round_ids(&self, height: u32) -> anyhow::Result<Vec<RoundId>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT id, tx, signed_tree, nb_input_vtxos, connector_key FROM round WHERE expiry > $1
		").await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;
		Ok(rows.map_ok(|row| StoredRound::try_from(row).expect("corrupt db").id).try_collect::<Vec<_>>().await?)
	}

	/**
	 * Sweeps
	*/

	/// Add the pending sweep tx.
	pub async fn store_pending_sweep(&self, txid: &Txid, tx: &Transaction) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare_typed("
			INSERT INTO pending_sweep (txid, tx) VALUES ($1, $2);
		", &[Type::TEXT, Type::BYTEA]).await?;
		conn.execute(
			&statement,
			&[&txid.to_string(), &serialize(tx)]
		).await?;

		Ok(())
	}

	/// Drop the pending sweep tx by txid.
	pub async fn drop_pending_sweep(&self, txid: &Txid) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;

		let statement = conn.prepare("
			UPDATE pending_sweep SET deleted_at = NOW() WHERE txid = $1;
		").await?;
		conn.execute(&statement, &[&txid.to_string()]).await?;

		Ok(())
	}

	/// Fetch all pending sweep txs.
	pub async fn fetch_pending_sweeps(&self) -> anyhow::Result<HashMap<Txid, Transaction>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT txid, tx FROM pending_sweep
		").await?;

		let rows = conn.query(&statement, &[]).await?;

		let pending_sweeps = rows
			.into_iter()
			.map(|row| -> anyhow::Result<(Txid, Transaction)> {
				let sweep = PendingSweep::try_from(row).expect("corrupt db");
				Ok((sweep.txid, sweep.tx))
			})
			.collect::<Result<HashMap<Txid, Transaction>, _>>()?;

		Ok(pending_sweeps)
	}

	/**
	 * Wallet
	*/

	pub async fn store_changeset(&self, wallet: WalletKind, c: &ChangeSet) -> anyhow::Result<()> {
		let mut buf = Vec::new();
		ciborium::into_writer(c, &mut buf).unwrap();

		let conn = self.pool.get().await?;
		let table = wallet_table(wallet);
		let statement = conn.prepare_typed(&format!("
			INSERT INTO {table} (content) VALUES ($1);
		"), &[Type::BYTEA]).await?;
		conn.execute(&statement, &[&buf]).await?;

		Ok(())
	}

	pub async fn read_aggregate_changeset(
		&self,
		wallet: WalletKind,
	) -> anyhow::Result<Option<ChangeSet>> {
		let conn = self.pool.get().await?;
		let table = wallet_table(wallet);
		let statement = conn.prepare(&format!("
			SELECT content FROM {table}
		")).await?;
		let rows = conn.query(&statement, &[]).await?;

		let mut ret = Option::<ChangeSet>::None;
		for row in rows {
			let value = row.get::<_, Vec<u8>>(0);
			let cs = ciborium::from_reader::<ChangeSet, _>(&*value)
				.context("corrupt db: changeset value")?;

			if let Some(ref mut r) = ret {
				r.merge(cs);
			} else {
				ret = Some(cs);
			}
		}

		Ok(ret)
	}
}

fn wallet_table(kind: WalletKind) -> &'static str {
	match kind {
		WalletKind::Rounds => "wallet_changeset",
	}
}
