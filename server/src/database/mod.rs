

mod embedded {
	use refinery::embed_migrations;
	embed_migrations!("src/database/migrations");
}
mod utils;

pub mod forfeits;
pub mod ln;
pub mod rounds;

mod model;
pub use model::*;


use std::borrow::Borrow;
use std::collections::HashMap;

use anyhow::Context;
use ark::arkoor::ArkoorPackageBuilder;
use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use bdk_wallet::{chain::Merge, ChangeSet};
use bitcoin::{Transaction, Txid};
use bitcoin::consensus::{serialize, deserialize};
use bitcoin::secp256k1::PublicKey;
use bitcoin_ext::BlockHeight;
use futures::{Stream, TryStreamExt, StreamExt};
use tokio_postgres::{types::Type, Client, GenericClient, NoTls};
use log::info;

use ark::{Vtxo, VtxoId, VtxoRequest};
use ark::encode::ProtocolEncoding;

use crate::wallet::WalletKind;
use crate::config::Postgres as PostgresConfig;


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
			data.push(vtxo.serialize());
			expiry.push(vtxo.expiry_height() as i32);
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
	pub async fn upsert_vtxos<V: Borrow<Vtxo>>(
		&self,
		vtxos: impl IntoIterator<Item = V>,
	) -> anyhow::Result<()> {
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
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<Vtxo>> + '_> {
		let conn = self.pool.get().await?;

		// TODO: maybe store kind in a column to filter board at the db level
		let statement = conn.prepare_typed("
			SELECT id, vtxo, expiry, oor_spent, forfeit_state, forfeit_round_id, board_swept FROM vtxo \
			WHERE expiry <= $1 AND board_swept = false
		", &[Type::INT4]).await?;

		let rows = conn.query_raw(&statement, &[&(height as i32)]).await?;

		//TODO(stevenroose) this is very inefficient but I suspect this code
		// will be deprecated soon
		Ok(rows.map_err(anyhow::Error::from).try_filter_map(|row| async {
			let vtxo = VtxoState::try_from(row).expect("corrupt db").vtxo;
			if !self.is_round_tx(vtxo.chain_anchor().txid).await? {
				Ok(Some(vtxo))
			} else {
				Ok(None)
			}
		}).fuse())
	}

	pub async fn mark_board_swept(&self, vtxo: &Vtxo) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;

		let statement = conn.prepare("
			UPDATE vtxo SET board_swept = true WHERE id = $1;
		").await?;

		conn.execute(&statement, &[&vtxo.id().to_string()]).await?;

		Ok(())
	}

	/// Get vtxos by id and ensure the order of the returned vtxos matches the order of the provided ids.
	async fn get_vtxos_by_id_with_client<T>(client: &T, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>>
		where T : GenericClient + Sized
	{
		let statement = client.prepare_typed("
			SELECT id, vtxo, expiry, oor_spent, forfeit_state, forfeit_round_id, board_swept
			FROM vtxo
			WHERE id = any($1);
		", &[Type::TEXT_ARRAY]).await?;

		let id_str = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
		let rows = client.query(&statement, &[&id_str]).await
			.context("Query get_vtxos_by_id failed")?;

		// Parse all rows
		let mut vtxos = rows.into_iter()
			.map(|row| {
				let vtxo = VtxoState::try_from(row)?;
				Ok((vtxo.vtxo.id(), vtxo))
			})
			.collect::<anyhow::Result<HashMap<_, _>>>()
			.context("Failed to parse VtxoState from database")?;

		// Bail if one of the id's could not be found
		if vtxos.len() != ids.len() {
			let missing = ids.into_iter().filter(|id| !vtxos.contains_key(id));
			return not_found!(missing, "vtxo does not exist");
		}

		Ok(ids.iter().map(|id| vtxos.remove(id).unwrap()).collect())
	}

	pub async fn get_vtxos_by_id(&self, ids: &[VtxoId]) -> anyhow::Result<Vec<VtxoState>> {
		let conn = self.pool.get().await?;
		Self::get_vtxos_by_id_with_client(&*conn, ids).await
	}

	/// Fetch all vtxos that have been forfeited.
	pub async fn fetch_all_forfeited_vtxos(
		&self,
	) -> anyhow::Result<impl Stream<Item = anyhow::Result<Vtxo>> + '_> {
		let conn = self.pool.get().await?;
		let stmt = conn.prepare("
			SELECT vtxo FROM vtxo WHERE forfeit_state IS NOT NULL
		").await?;

		let params: Vec<String> = vec![];
		Ok(conn.query_raw(&stmt, params).await?
			.err_into()
			.map_ok(|row| Vtxo::deserialize(row.get("vtxo")).expect("corrupt db: vtxo"))
		)
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
		let mut conn = self.pool.get().await?;
		let tx = conn.transaction().await?;

		let new_vtxos = builder.new_vtxos().into_iter().flatten().collect::<Vec<_>>();

		for input in builder.inputs() {
			let txid = builder.spending_tx(input.id())
				.expect("spending tx should be present").compute_txid();

			let statement = tx.prepare_typed("
				UPDATE vtxo SET oor_spent = $2 WHERE id = $1;
			", &[Type::TEXT, Type::BYTEA]).await?;

			let vtxos = Self::get_vtxos_by_id_with_client(&tx, &[input.id()]).await?;
			for vtxo_state in vtxos {
				if !vtxo_state.is_spendable() {
					return Ok(Some(vtxo_state.id));
				}

				tx.execute(&statement, &[&vtxo_state.id.to_string(), &serialize(&txid)]).await?;
			}
		}

		Self::inner_upsert_vtxos(&tx, new_vtxos).await?;

		tx.commit().await?;
		Ok(None)
	}

	/**
	 * Arkoors
	*/

	pub async fn store_oor(&self, pubkey: PublicKey, arkoor_package_id: &[u8; 32], vtxo: Vtxo) -> anyhow::Result<()> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			INSERT INTO arkoor_mailbox (id, pubkey, arkoor_package_id, vtxo) VALUES ($1, $2, $3, $4);
		").await?;
		conn.execute(&statement, &[
			&vtxo.id().to_string(),
			&pubkey.serialize().to_vec(),
			&arkoor_package_id.to_vec(),
			&vtxo.serialize(),
		]).await?;

		Ok(())
	}

	pub async fn pull_oors(
		&self,
		pubkeys: &[PublicKey],
	) -> anyhow::Result<HashMap<[u8; 32], Vec<Vtxo>>> {
		let conn = self.pool.get().await?;
		let statement = conn.prepare("
			SELECT vtxo, arkoor_package_id FROM arkoor_mailbox WHERE pubkey = ANY($1)
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
			UPDATE arkoor_mailbox SET deleted_at = NOW() WHERE pubkey = ANY($1);
		").await?;
		let result = conn.execute(&statement, &[&serialized_pubkeys]).await?;
		assert_eq!(result, rows.len() as u64);

		Ok(vtxos_by_package_id)
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

	// **********
	// * WALLET *
	// **********

	pub async fn store_changeset(&self, wallet: WalletKind, c: &ChangeSet) -> anyhow::Result<()> {
		let bytes = rmp_serde::to_vec_named(c).expect("serde serialization");

		let conn = self.pool.get().await?;
		let table = wallet_table(wallet);
		let statement = conn.prepare_typed(&format!("
			INSERT INTO {table} (content) VALUES ($1);
		"), &[Type::BYTEA]).await?;
		conn.execute(&statement, &[&bytes]).await?;

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
		let conn = self.pool.get().await?;
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
		let conn = self.pool.get().await?;
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
}

fn wallet_table(kind: WalletKind) -> &'static str {
	match kind {
		WalletKind::Rounds => "wallet_changeset",
		WalletKind::Forfeits => "forfeits_wallet_changeset",
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
