use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use bitcoin::{Amount, BlockHash, FeeRate, Network, Txid};
use bitcoin::consensus;
use bitcoin::bip32::Fingerprint;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use rusqlite::{self, named_params, Connection, ToSql};

use bitcoin_ext::{BlockHeight, BlockRef};
use json::exit::ExitState;

use crate::persist::{OffchainBoard, OffchainPayment};
use crate::vtxo_state::{VtxoStateKind, WalletVtxo};
use crate::{
	Config, KeychainKind, Pagination, Vtxo, VtxoId, VtxoState,
	WalletProperties,
};
use crate::exit::vtxo::ExitEntry;
use crate::movement::Movement;
use ark::ProtocolEncoding;

use super::convert::{row_to_movement, row_to_offchain_board};

/// Set read-only properties for the wallet
///
/// This is fail if properties aren't already set for the wallet
pub (crate) fn set_properties(
	conn: &Connection,
	properties: &WalletProperties,
) -> anyhow::Result<()> {
	// Store the ftxo
	let query =
		"INSERT INTO bark_properties (id, network, fingerprint)
		VALUES (1, :network, :fingerprint)";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":network": properties.network.to_string(),
		":fingerprint": properties.fingerprint.to_string(),
	})?;

	Ok(())
}

pub (crate) fn set_config(conn: &Connection, config: &Config) -> anyhow::Result<()> {
	// Store the ftxo
	let query =
		"INSERT INTO bark_config
			(id, asp_address, esplora_address, bitcoind_address,
			bitcoind_cookiefile, bitcoind_user, bitcoind_pass, vtxo_refresh_expiry_threshold,
			fallback_fee_kwu)
		VALUES
			(1, :asp_address, :esplora_address, :bitcoind_address,
			:bitcoind_cookiefile, :bitcoind_user, :bitcoind_pass, :vtxo_refresh_expiry_threshold,
			:fallback_fee_kwu)
		ON CONFLICT (id)
		DO UPDATE SET
			asp_address = :asp_address,
			esplora_address = :esplora_address,
			bitcoind_address = :bitcoind_address,
			bitcoind_cookiefile = :bitcoind_cookiefile,
			bitcoind_user = :bitcoind_user,
			bitcoind_pass = :bitcoind_pass,
			vtxo_refresh_expiry_threshold = :vtxo_refresh_expiry_threshold,
			fallback_fee_kwu = :fallback_fee_kwu
		";
	let mut statement = conn.prepare(query)?;

	statement.execute(named_params! {
		":asp_address": config.asp_address,
		":esplora_address": config.esplora_address,
		":bitcoind_address": config.bitcoind_address,
		":bitcoind_cookiefile": config.bitcoind_cookiefile
			.clone().and_then(|f| f.to_str().map(String::from)),
		":bitcoind_user": config.bitcoind_user,
		":bitcoind_pass": config.bitcoind_pass,
		":vtxo_refresh_expiry_threshold": config.vtxo_refresh_expiry_threshold,
		":fallback_fee_kwu": config.fallback_fee_rate.map(|f| f.to_sat_per_kwu()),
	})?;

	Ok(())
}

pub (crate) fn fetch_properties(conn: &Connection) -> anyhow::Result<Option<WalletProperties>> {
	let query = "SELECT * FROM bark_properties";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let network: String = row.get("network")?;
		let fingerprint: String = row.get("fingerprint")?;

		Ok(Some(
			WalletProperties {
				network: Network::from_str(&network).context("invalid network")?,
				fingerprint: Fingerprint::from_str(&fingerprint).context("invalid fingerprint")?,
			}
		))
	} else {
		Ok(None)
	}
}

pub (crate) fn fetch_config(conn: &Connection) -> anyhow::Result<Option<Config>> {
	let query = "SELECT * FROM bark_config";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let bitcoind_cookiefile_opt: Option<String> = row.get("bitcoind_cookiefile")?;
		let bitcoind_cookiefile = if let Some (bitcoind_cookiefile) = bitcoind_cookiefile_opt {
			Some(PathBuf::try_from(bitcoind_cookiefile)?)
		} else {
			None
		};

		let kwu_fee: Option<u64> = row.get("fallback_fee_kwu")?;
		Ok(Some(
			Config {
				asp_address: row.get("asp_address")?,
				esplora_address: row.get("esplora_address")?,
				bitcoind_address: row.get("bitcoind_address")?,
				bitcoind_cookiefile,
				bitcoind_user: row.get("bitcoind_user")?,
				bitcoind_pass: row.get("bitcoind_pass")?,
				vtxo_refresh_expiry_threshold: row.get("vtxo_refresh_expiry_threshold")?,
				fallback_fee_rate: kwu_fee.map(|f| FeeRate::from_sat_per_kwu(f)),
			}
		))
	} else {
		Ok(None)
	}
}

pub fn create_movement(conn: &Connection, fees_sat: Option<Amount>) -> anyhow::Result<i32> {
	// Store the vtxo
	let query = "INSERT INTO bark_movement (fees_sat) VALUES (:fees_sat) RETURNING *;";
	let mut statement = conn.prepare(query)?;
	let movement_id = statement.query_row(named_params! {
		":fees_sat" : fees_sat.unwrap_or(Amount::ZERO).to_sat()
	}, |row| row.get::<_, i32>(0))?;

	Ok(movement_id)
}

pub fn create_recipient(
	conn: &Connection,
	movement: i32,
	recipient: &str,
	amount: Amount,
) -> anyhow::Result<i32> {
	// Store the vtxo
	let query = "
		INSERT INTO bark_recipient (movement, recipient, amount_sat)
		VALUES (:movement, :recipient, :amount_sat) RETURNING *;";

	let mut statement = conn.prepare(query)?;
	let recipient_id = statement.query_row(named_params! {
		":movement": movement,
		":recipient" : recipient,
		":amount_sat": amount.to_sat()
	}, |row| row.get::<_, i32>(0))?;

	Ok(recipient_id)
}

pub fn check_recipient_exists(conn: &Connection, recipient: &str) -> anyhow::Result<bool> {
	let query = "SELECT COUNT(*) FROM bark_recipient WHERE recipient = :recipient";

	let mut statement = conn.prepare(query)?;
	let exists = statement.query_row(named_params! {
		":recipient" : recipient,
	}, |row| Ok(row.get::<_, i32>(0)? > 0))?;

	Ok(exists)
}

pub fn get_paginated_movements(conn: &Connection, pagination: Pagination) -> anyhow::Result<Vec<Movement>> {
	let take = pagination.page_size;
	let skip = pagination.page_index * take;

	let query = "
		SELECT * FROM movement_view
		ORDER BY movement_view.created_at DESC
		LIMIT :take
		OFFSET :skip
	";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(named_params! {
		":take" : take,
		":skip" : skip,
	})?;

	let mut movements = Vec::with_capacity(take as usize);
	while let Some(row) = rows.next()? {
		movements.push(row_to_movement(row)?);
	}

	Ok(movements)
}

pub fn store_vtxo_with_initial_state(
	tx: &rusqlite::Transaction,
	vtxo: &Vtxo,
	movement_id: i32,
	state: &VtxoState,
) -> anyhow::Result<()> {
	// Store the ftxo
	let q1 =
		"INSERT INTO bark_vtxo (id, expiry_height, amount_sat, received_in, raw_vtxo)
		VALUES (:vtxo_id, :expiry_height, :amount_sat, :received_in, :raw_vtxo);";
	let mut statement = tx.prepare(q1)?;
	statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.expiry_height(),
		":amount_sat": vtxo.amount().to_sat(),
		":received_in": movement_id,
		":raw_vtxo": vtxo.serialize(),
	})?;

	// Store the initial state
	let q2 =
		"INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
		VALUES (:vtxo_id, :state_kind, :state);";
	let mut statement = tx.prepare(q2)?;
	statement.execute(named_params! {
		":vtxo_id": vtxo.id().to_string(),
		":state_kind": state.as_kind().as_str(),
		":state": serde_json::to_vec(&state)?,
	})?;

	Ok(())
}

pub fn get_wallet_vtxo_by_id(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<WalletVtxo>> {
	let query = "SELECT raw_vtxo, state FROM vtxo_view WHERE id = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let vtxo = Vtxo::deserialize(&row.get::<_, Vec<u8>>("raw_vtxo")?)?;
		let state = serde_json::from_slice::<VtxoState>(&row.get::<_, Vec<u8>>("state")?)?;
		Ok(Some(WalletVtxo { vtxo, state }))
	} else {
		Ok(None)
	}
}

pub fn get_vtxos_by_state(
	conn: &Connection,
	state: &[VtxoStateKind]
) -> anyhow::Result<Vec<WalletVtxo>> {
	let query = "
		SELECT raw_vtxo, state
		FROM vtxo_view
		WHERE state_kind IN (SELECT atom FROM json_each(?))
		ORDER BY amount_sat DESC, expiry_height ASC";

	let mut statement = conn.prepare(query)?;

	let mut rows = statement.query(&[&serde_json::to_string(&state)?])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo = {
			let raw_vtxo : Vec<u8> = row.get("raw_vtxo")?;
			Vtxo::deserialize(&raw_vtxo)?
		};

		let state = {
			let raw_state : Vec<u8> = row.get("state")?;
			serde_json::from_slice::<VtxoState>(&raw_state)?
		};

		result.push(WalletVtxo { vtxo, state });
	}
	Ok(result)
}

pub fn delete_vtxo(
	tx: &rusqlite::Transaction,
	id: VtxoId
) -> anyhow::Result<Option<Vtxo>> {
	// Delete all vtxo-states
	let query = "DELETE FROM bark_vtxo_state WHERE vtxo_id = ?1";
	tx.execute(query, [id.to_string()])?;

	let query = "DELETE FROM bark_vtxo WHERE id = ?1 RETURNING raw_vtxo";
	let mut statement = tx.prepare(query)?;

	let vtxo = statement
		.query_and_then(
			[id.to_string()],
			|row| -> anyhow::Result<Vtxo> {
				let raw_vtxo : Vec<u8> = row.get(0)?;
				Ok(Vtxo::deserialize(&raw_vtxo)?)
			})?
		.filter_map(|x| x.ok())
		.next();

	Ok(vtxo)
}

pub fn get_vtxo_state(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<VtxoState>> {
	let query =
		"SELECT state
		FROM bark_vtxo_state
		WHERE vtxo_id = ?1
		ORDER BY created_at DESC LIMIT 1";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let state = row.get::<_, Vec<u8>>(0)?;
		Ok(Some(serde_json::from_slice(&state)?))
	} else {
		Ok(None)
	}
}

pub fn link_spent_vtxo_to_movement(
	conn: &Connection,
	id: VtxoId,
	movement_id: i32
) -> anyhow::Result<()> {
	let query = "UPDATE bark_vtxo SET spent_in = :spent_in WHERE id = :vtxo_id";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":vtxo_id": id.to_string(),
		":spent_in": movement_id
	})?;

	Ok(())
}

/// Updates the state of a VTXO from one of the
/// values in `old_state` to `new_state`.
///
/// The method is atomic. If another process tries
/// to update the state only one of them will succeed.
///
/// If an error is reported the state will remain unchanged.
pub fn update_vtxo_state_checked(
	conn: &Connection,
	vtxo_id: VtxoId,
	new_state: VtxoState,
	old_states: &[VtxoStateKind],
) -> anyhow::Result<WalletVtxo> {
	let query = r"
		INSERT INTO bark_vtxo_state (vtxo_id, state_kind, state)
		SELECT :vtxo_id, :state_kind, :state FROM most_recent_vtxo_state
		WHERE
			vtxo_id = :vtxo_id AND
			state_kind IN (SELECT atom FROM json_each(:old_states))";

	let mut statement = conn.prepare(query)?;
	let nb_inserted = statement.execute(named_params! {
		":vtxo_id": vtxo_id.to_string(),
		":state_kind": new_state.as_kind().as_str(),
		":state": serde_json::to_vec(&new_state)?,
		":old_states": &serde_json::to_string(old_states)?,
	})?;

	match nb_inserted {
		0 => bail!("No vtxo with provided id or old states"),
		1 => Ok(get_wallet_vtxo_by_id(conn, vtxo_id)?.unwrap()),
		_ => panic!("Corrupted database. A vtxo can have only one state"),
	}
}

pub fn store_vtxo_key(
	conn: &Connection,
	keychain: KeychainKind,
	index: u32,
	public_key: PublicKey
) -> anyhow::Result<()> {
	let query = "INSERT INTO bark_vtxo_key (keychain, idx, public_key) VALUES (?1, ?2, ?3);";
	let mut statement = conn.prepare(query)?;
	statement.execute([keychain.to_sql()?, index.to_sql()?, public_key.to_string().to_sql()?])?;
	Ok(())
}

pub fn get_vtxo_key(conn: &Connection, vtxo: &Vtxo) -> anyhow::Result<Option<(KeychainKind, u32)>> {
	let query = "SELECT keychain, idx FROM bark_vtxo_key WHERE public_key = (?1)";
	let pk = vtxo.user_pubkey().to_string();

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((pk, ))?;

	if let Some(row) = rows.next()? {
		let index = u32::try_from(row.get::<_, i64>("idx")?)?;
		let keychain = KeychainKind::try_from(row.get::<_, i64>("keychain")?)?;
		Ok(Some((keychain, index)))
	} else {
		Ok(None)
	}
}

pub fn check_vtxo_key_exists(conn: &Connection, public_key: &PublicKey) -> anyhow::Result<bool> {
	let query = "SELECT idx FROM bark_vtxo_key WHERE public_key = (?1)";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((public_key.to_string(), ))?;

	Ok(rows.next()?.is_some())
}

pub fn get_last_vtxo_key_index(conn: &Connection, keychain: KeychainKind) -> anyhow::Result<Option<u32>> {
	let query = "SELECT idx FROM bark_vtxo_key WHERE keychain = ?1 ORDER BY idx DESC LIMIT 1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((keychain.to_sql()?, ))?;

	if let Some(row) = rows.next()? {
		let index = u32::try_from(row.get::<usize, i64>(0)?)?;
		Ok(Some(index))
	} else {
		Ok(None)
	}
}

pub fn store_last_ark_sync_height(
	conn: &Connection,
	height: BlockHeight
) -> anyhow::Result<()> {
	let query = "INSERT INTO bark_ark_sync (sync_height) VALUES (?1);";
	let mut statement = conn.prepare(query)?;
	statement.execute([height])?;
	Ok(())
}

pub fn get_last_ark_sync_height(conn: &Connection) -> anyhow::Result<BlockHeight> {
	// This query orders on id and not on the created_at field
	// Using creatd_at would be more readable, however, this might break
	// if two subsequent rows are added in the same millisecond.
	let query = "SELECT sync_height FROM bark_ark_sync ORDER BY id DESC LIMIT 1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query(())?;

	if let Some(row) = rows.next()? {
		let height_i64 : i64 = row.get(0)?;
		let height = u32::try_from(height_i64)?;
		Ok(height)
	} else {
		Ok(0)
	}
}

pub fn store_offchain_board(
	conn: &Connection,
	payment_hash: &[u8; 32],
	preimage: &[u8; 32],
	payment: OffchainPayment,
) -> anyhow::Result<()> {
	let query = "
		INSERT INTO bark_offchain_board (payment_hash, preimage, serialised_payment)
		VALUES (?1, ?2, ?3);
	";
	let mut statement = conn.prepare(query)?;

	statement.execute([
		payment_hash.to_vec(),
		preimage.to_vec(),
		serde_json::to_vec(&payment)?,
	])?;

	Ok(())
}

pub fn fetch_offchain_board_by_payment_hash(conn: &Connection, payment_hash: &[u8; 32]) -> anyhow::Result<Option<OffchainBoard>> {
	let query = "SELECT * FROM bark_offchain_board WHERE payment_hash = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query((payment_hash, ))?;

	Ok(rows.next()?.map(|row| row_to_offchain_board(&row)).transpose()?)
}

pub fn store_exit_vtxo_entry(tx: &rusqlite::Transaction, exit: &ExitEntry) -> anyhow::Result<()> {
	let query = r"
		INSERT INTO bark_exit_states (vtxo_id, state, history)
		VALUES (?1, ?2, ?3)
		ON CONFLICT (vtxo_id) DO UPDATE
		SET
			state = EXCLUDED.state,
			history = EXCLUDED.history;
	";

	// We can't use JSONB with rusqlite, so we make do with strings
	let id = exit.vtxo_id.to_string();
	let state = serde_json::to_string(&exit.state)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} state can't be serialized: {}", id, e))?;
	let history = serde_json::to_string(&exit.history)
		.map_err(|e| anyhow::format_err!("Exit VTXO {} history can't be serialized: {}", id, e))?;

	tx.execute(query, (id, state, history))?;
	Ok(())
}

pub fn remove_exit_vtxo_entry(tx: &rusqlite::Transaction, id: &VtxoId) -> anyhow::Result<()> {
	let query = "DELETE FROM bark_exit_states WHERE vtxo_id = ?1;";
	tx.execute(query, [id.to_string()])?;

	Ok(())
}

pub fn get_exit_vtxo_entries(conn: &Connection) -> anyhow::Result<Vec<ExitEntry>> {
	let mut statement = conn.prepare("SELECT vtxo_id, state, history FROM bark_exit_states;")?;
	let mut rows = statement.query([])?;
	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let vtxo_id = VtxoId::from_str(&row.get::<usize, String>(0)?)?;
		let state = serde_json::from_str::<ExitState>(&row.get::<usize, String>(1)?)?;
		let history = serde_json::from_str::<Vec<ExitState>>(&row.get::<usize, String>(2)?)?;

		result.push(ExitEntry { vtxo_id, state, history });
	}

	Ok(result)
}

pub fn store_exit_child_tx(
	tx: &rusqlite::Transaction,
	exit_txid: Txid,
	child_tx: &bitcoin::Transaction,
	block: Option<BlockRef>,
) -> anyhow::Result<()> {
	let query = r"
		INSERT INTO bark_exit_child_transactions (exit_id, child_tx, block_hash, height)
		VALUES (?1, ?2, ?3, ?4)
		ON CONFLICT (exit_id) DO UPDATE
		SET
			child_tx = EXCLUDED.child_tx,
			block_hash = EXCLUDED.block_hash,
			height = EXCLUDED.height
	";

	let exit_id = exit_txid.to_string();
	let child_transaction = consensus::serialize(child_tx);
	let (height, hash) = if let Some(block) = block {
		(Some(block.height), Some(consensus::serialize(&block.hash)))
	} else {
		(None, None)
	};
	tx.execute(query, (exit_id, child_transaction, hash, height))?;
	Ok(())
}

pub fn get_exit_child_tx(
	conn: &Connection,
	exit_txid: Txid,
) -> anyhow::Result<Option<(bitcoin::Transaction, Option<BlockRef>)>> {
	let query = r"
			SELECT child_tx, block_hash, height FROM bark_exit_child_transactions where exit_id = ?1;
		";
	let mut statement = conn.prepare(query)?;
	let result = statement.query_row([exit_txid.to_string()], |row| {
		let tx_bytes : Vec<u8> = row.get(0)?;
		let tx = consensus::deserialize(&tx_bytes)
			.map_err(|e| rusqlite::Error::FromSqlConversionFailure(
				tx_bytes.len(), rusqlite::types::Type::Blob, Box::new(e)
			))?;
		let block = {
			let hash_bytes : Option<Vec<u8>> = row.get(1)?;
			let height : Option<u32> = row.get(2)?;
			match (hash_bytes, height) {
				(Some(bytes), Some(height)) => {
					let hash = BlockHash::from_slice(&bytes)
						.map_err(|e| rusqlite::Error::FromSqlConversionFailure(
							tx_bytes.len(), rusqlite::types::Type::Blob, Box::new(e)
						))?;
					Some(BlockRef { hash, height })
				},
				(None, None) => None,
				_ => panic!("Invalid data in database")
			}
		};
		Ok((tx, block))
	});
	match result {
		Ok(result) => Ok(Some(result)),
		Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
		Err(e) => Err(format_err!("Unable to deserialize child tx for exit {}: {}", exit_txid, e)),
	}
}



#[cfg(test)]
mod test {
	use ark::vtxo::test::VTXO_VECTORS;
	use crate::movement::{MovementRecipient, VtxoSubset};
	use crate::persist::sqlite::test::in_memory;
	use crate::persist::sqlite::migrations::MigrationContext;
	use super::*;

	#[test]
	fn test_update_vtxo_state() {
		let (_, mut conn) = in_memory();
		MigrationContext{}.do_all_migrations(&mut conn).unwrap();

		let tx = conn.transaction().unwrap();
		let vtxo_1 = &VTXO_VECTORS.board_vtxo;
		let vtxo_2 = &VTXO_VECTORS.arkoor_htlc_out_vtxo;
		let vtxo_3 = &VTXO_VECTORS.round2_vtxo;

		let movement_id = create_movement(&tx, None).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_1, movement_id, &VtxoState::UnregisteredBoard).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_2, movement_id, &VtxoState::UnregisteredBoard).unwrap();
		store_vtxo_with_initial_state(&tx, &vtxo_3, movement_id, &VtxoState::UnregisteredBoard).unwrap();

		// This update will fail because the current state is UnregisteredBoard
		// We only allow the state to switch from VtxoState::Spendable
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable])
			.expect_err("The vtxo isn't spendable and query should fail");

		// Perform a state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spendable, &[VtxoStateKind::UnregisteredBoard]).unwrap();

		// Perform a second state-update on vtxo_1
		update_vtxo_state_checked(&tx, vtxo_1.id(), VtxoState::Spent, &[VtxoStateKind::Spendable]).unwrap();

		// Ensure the state of vtxo_2 and vtxo_3 isn't modified
		let state_2 = get_vtxo_state(&tx, vtxo_2.id()).unwrap().unwrap();
		assert_eq!(state_2, VtxoState::UnregisteredBoard);
		let state_2 = get_vtxo_state(&tx, vtxo_3.id()).unwrap().unwrap();
		assert_eq!(state_2, VtxoState::UnregisteredBoard);
	}


	#[test]
	/// Each struct stored as JSON in the database should have test to check for backwards compatibility
	/// Parsing can occur either in convert.rs or this file (query.rs)
	fn test_serialised_offchain_payment() {
		// Offchain payment
		let serialised = r#"{"Lightning":"lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8"}"#;
		serde_json::from_str::<OffchainPayment>(serialised).unwrap();

		// Exit state
		let serialised = r#"{"type":"start","tip_height":119}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"processing","tip_height":119,"transactions":[{"txid":"9fd34b8c556dd9954bda80ba2cf3474a372702ebc31a366639483e78417c6812","status":{"type":"awaiting-input-confirmation","txids":["ddfe11920358d1a1fae970dc80459c60675bf1392896f69b103fc638313751de"]}}]}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"awaiting-delta","tip_height":122,"confirmed_block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"},"spendable_height":134}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spendable","tip_height":134,"spendable_since":{"height":134,"hash":"71fe28f4c803a4c46a3a93d0a9937507d7c20b4bd9586ba317d1109e1aebaac9"},"last_scanned_block":null}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spend-in-progress","tip_height":134,"spendable_since":{"height":134,"hash":"6585896bdda6f08d924bf45cc2b16418af56703b3c50930e4dccbc1728d3800a"},"spending_txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c"}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();
		let serialised = r#"{"type":"spent","tip_height":134,"txid":"599347c35870bd36f7acb22b81f9ffa8b911d9b5e94834858aebd3ec09339f4c","block":{"height":122,"hash":"3cdd30fc942301a74666c481beb82050ccd182050aee3c92d2197e8cad427b8f"}}"#;
		serde_json::from_str::<ExitState>(serialised).unwrap();

		// Vtxo subset
		let serialised = r#"{"id":"1570ed0ccb55520cc343628ad95e325010983c61655580bfea10e067d98f40af:0","amount_sat":300000}"#;
		serde_json::from_str::<VtxoSubset>(serialised).unwrap();

		// Movement recipient
		let serialised = r#"{"recipient":"03a4a6443868dbba406d03e43d7baf00d66809d57fba911616ccf90a4685de2bc1","amount_sat":150000}"#;
		serde_json::from_str::<MovementRecipient>(serialised).unwrap();

		// Vtxo state
		let serialised = r#""Spendable""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""Spent""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#""UnregisteredBoard""#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();
		let serialised = r#"{"PendingLightningSend":{"invoice":"lnbcrt11p59rr6msp534kz2tahyrxl0rndcjrt8qpqvd0dynxxwfd28ea74rxjuj0tphfspp5nc0gf6vamuphaf4j49qzjvz2rg3del5907vdhncn686cj5yykvfsdqqcqzzs9qyysgqgalnpu3selnlgw8n66qmdpuqdjpqak900ru52v572742wk4mags8a8nec2unls57r5j95kkxxp4lr6wy9048uzgsvdhrz7dh498va2cq4t6qh8","amount":300000}}"#;
		serde_json::from_str::<VtxoState>(serialised).unwrap();

	}
}
