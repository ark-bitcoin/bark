use std::{path::PathBuf, str::FromStr};
use anyhow::Context;
use ark::Movement;
use bitcoin::{bip32::Fingerprint, Amount, Network};
use rusqlite::{Connection, named_params, Transaction};
use crate::{exit::Exit, Config, Pagination, Vtxo, VtxoId, VtxoState, WalletProperties};

/// Set read-only properties for the wallet
/// 
/// This is fail if properties aren't already set for the wallet
pub (crate) fn set_properties(
	conn: &Connection,
	properties: &WalletProperties,
) -> anyhow::Result<()> {
	// Store the ftxo
	let query = 
		"INSERT INTO properties (id, network, fingerprint) 
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
		"INSERT INTO config 
			(id, asp_address, esplora_address, bitcoind_address, 
			bitcoind_cookiefile, bitcoind_user, bitcoind_pass, vtxo_refresh_threshold) 
		VALUES 
			(1, :asp_address, :esplora_address, :bitcoind_address, 
			:bitcoind_cookiefile, :bitcoind_user, :bitcoind_pass, :vtxo_refresh_threshold)
		ON CONFLICT (id)	
		DO UPDATE SET
			asp_address = :asp_address,
			esplora_address = :esplora_address,
			bitcoind_address = :bitcoind_address,
			bitcoind_cookiefile = :bitcoind_cookiefile,
			bitcoind_user = :bitcoind_user,
			bitcoind_pass = :bitcoind_pass,
			vtxo_refresh_threshold = :vtxo_refresh_threshold
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
		":vtxo_refresh_threshold": config.vtxo_refresh_threshold,
	})?;

	Ok(())
}

pub (crate) fn fetch_properties(conn: &Connection) -> anyhow::Result<Option<WalletProperties>> {
	let query = "SELECT * FROM properties";
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
	let query = "SELECT * FROM config";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let bitcoind_cookiefile_opt: Option<String> = row.get("bitcoind_cookiefile")?;
		let bitcoind_cookiefile = if let Some (bitcoind_cookiefile) = bitcoind_cookiefile_opt {
			Some(PathBuf::try_from(bitcoind_cookiefile)?)
		} else {
			None
		};

		Ok(Some(
			Config {
				asp_address: row.get("asp_address")?,
				esplora_address: row.get("esplora_address")?,
				bitcoind_address: row.get("bitcoind_address")?,
				bitcoind_cookiefile: bitcoind_cookiefile,
				bitcoind_user: row.get("bitcoind_user")?,
				bitcoind_pass: row.get("bitcoind_pass")?,
				vtxo_refresh_threshold: row.get("vtxo_refresh_threshold")?,
			}
		))
	} else {
		Ok(None)
	}
}

pub fn create_movement(conn: &Connection, fees_sat: Option<Amount>, destination: Option<String>) -> anyhow::Result<i32> {
	// Store the vtxo
	let query = "INSERT INTO movement (fees_sat, destination) VALUES (:fees_sat, :destination) RETURNING *;";
	let mut statement = conn.prepare(query)?;	
	let movement_id = statement.query_row(named_params! {
		":fees_sat" : fees_sat.unwrap_or(Amount::ZERO).to_sat(),
		":destination": destination
	}, |row| row.get::<_, i32>(0))?;

	Ok(movement_id)
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
		let fees = Amount::from_sat(row.get("fees_sat")?);
		let spends: String = row.get("spends")?;
		let receives: String = row.get("receives")?;

		movements.push(Movement {
			id: row.get("id")?,
			destination: row.get("destination")?,
			fees: fees,
			created_at: row.get("created_at")?,
			spends: serde_json::from_str(&spends)?,
			receives: serde_json::from_str(&receives)?,
		});
	}

	Ok(movements)
}

pub fn store_vtxo_with_initial_state(
	tx: &Transaction,
	vtxo: &Vtxo,
	movement_id: i32,
	state: VtxoState
) -> anyhow::Result<()> {
	// Store the ftxo
	let q1 = 
		"INSERT INTO vtxo (id, expiry_height, amount_sat, received_in, raw_vtxo) 
		VALUES (:vtxo_id, :expiry_height, :amount_sat, :received_in, :raw_vtxo);";
	let mut statement = tx.prepare(q1)?;
	statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.spec().expiry_height,
		":amount_sat": vtxo.amount().to_sat(),
		":received_in": movement_id,
		":raw_vtxo": vtxo.encode(),
	})?;

	// Store the initial state
	let q2 = 
		"INSERT INTO vtxo_state (vtxo_id, state) 
		VALUES (:vtxo_id, :state);";
	let mut statement = tx.prepare(q2)?;
	statement.execute(named_params! {
		":vtxo_id": vtxo.id().to_string(),
		":state": state.to_string()
	})?;

	Ok(())
}

pub fn get_vtxo_by_id(
	conn: &Connection,
	id: VtxoId
) -> anyhow::Result<Option<Vtxo>> {
	let query = "SELECT raw_vtxo FROM vtxo WHERE id = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let raw_vtxo : Vec<u8> = row.get("raw_vtxo")?;
		let vtxo = Vtxo::decode(&raw_vtxo)?;
		Ok(Some(vtxo))
	} else {
		Ok(None)
	}
}

pub fn get_vtxos_by_state(
	conn: &Connection,
	state: VtxoState
) -> anyhow::Result<Vec<Vtxo>> {
	let query = "SELECT raw_vtxo FROM vtxo_view WHERE state = ?1";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([state.to_string()])?;

	let mut result = Vec::new();
	while let Some(row) = rows.next()? {
		let raw_vtxo : Vec<u8> = row.get("raw_vtxo")?;
		let vtxo = Vtxo::decode(&raw_vtxo)?;
		result.push(vtxo);
	}
	Ok(result)
}

pub fn get_expiring_vtxos(
	conn: &Connection,
	value: Amount
) -> anyhow::Result<Vec<Vtxo>> {
	let query = 
		"SELECT raw_vtxo, amount_sat
		FROM vtxo_view 
		WHERE state = ?1
		ORDER BY expiry_height ASC";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([VtxoState::Ready])?;

	// Iterate over all rows until the required amount is reached
	let mut result = Vec::new();
	let mut total_amount = bitcoin::Amount::ZERO;
	while let Some(row) = rows.next()? {
		let raw_vtxo : Vec<u8> = row.get("raw_vtxo")?;
		let vtxo_amount_sat : i64 = row.get("amount_sat")?;
		
		let vtxo = Vtxo::decode(&raw_vtxo)?;
		let vtxo_amount = Amount::from_sat(u64::try_from(vtxo_amount_sat)?);

		total_amount += vtxo_amount;
		result.push(vtxo);

		if total_amount >= value {
			return Ok(result)
		}
	}
	bail!(
		"Insufficient money available. Needed {} but {} is available", 
		value,
		total_amount);
}

pub fn delete_vtxo(
	tx: &Transaction,
	id: VtxoId
) -> anyhow::Result<Option<Vtxo>> {
	// Delete all vtxo-states
	let query = "DELETE FROM vtxo_state WHERE vtxo_id = ?1";
	tx.execute(query, [id.to_string()])?;

	let query = "DELETE FROM vtxo WHERE id = ?1 RETURNING raw_vtxo";
	let mut statement = tx.prepare(query)?;

	let vtxo = statement
		.query_and_then(
			[id.to_string()],
			|row| -> anyhow::Result<Vtxo> {
				let raw_vtxo : Vec<u8> = row.get(0)?;
				Ok(Vtxo::decode(&raw_vtxo)?)
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
		FROM vtxo_state
		WHERE vtxo_id = ?1
		ORDER BY created_at DESC LIMIT 1";

	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([id.to_string()])?;

	if let Some(row) = rows.next()? {
		let state_str : String= row.get(0)?;
		Ok(Some(VtxoState::from_str(&state_str)?))
	} else {
		Ok(None)
	}
}

pub fn link_spent_vtxo_to_movement(
	conn: &Connection,
	id: VtxoId,
	movement_id: i32
) -> anyhow::Result<()> {
	let query = "UPDATE vtxo SET spent_in = :spent_in WHERE id = :vtxo_id";
	let mut statement = conn.prepare(query)?;
	statement.execute(named_params! {
		":vtxo_id": id.to_string(),
		":spent_in": movement_id
	})?;

	Ok(())
}

pub fn update_vtxo_state(
	conn: &Connection,
	id: VtxoId,
	state: VtxoState
) -> anyhow::Result<()> {
	let query = "INSERT INTO vtxo_state (vtxo_id, state) VALUES (?1, ?2)";
	let mut statement = conn.prepare(query)?;
	statement.execute([id.to_string(), state.to_string()])?;
	Ok(())
}

pub fn store_last_ark_sync_height(
	conn: &Connection,
	height: u32
) -> anyhow::Result<()> {
	let query = "INSERT INTO ark_sync (sync_height) VALUES (?1);";
	let mut statement = conn.prepare(query)?;
	statement.execute([height])?;
	Ok(())
}

pub fn get_last_ark_sync_height(conn: &Connection) -> anyhow::Result<u32> {
	// This query orders on id and not on the created_at field
	// Using creatd_at would be more readable, however, this might break
	// if two subsequent rows are added in the same millisecond.
	let query = "SELECT sync_height FROM ark_sync ORDER BY id DESC LIMIT 1";
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

pub fn store_exit(tx: &Transaction, exit: &Exit) -> anyhow::Result<()> {
	let mut buf = Vec::new();
	ciborium::into_writer(exit, &mut buf)?;

	// Exits are somehwat large, we only want one in the database
	// That's why we delete the old one and add the new one later
	tx.execute("DELETE FROM exit", [])?;
	tx.execute("INSERT INTO exit (exit) VALUES (?1)", [buf])?;
	Ok(())
}

pub fn fetch_exit(conn: &Connection) -> anyhow::Result<Option<Exit>> {
	let mut statement = conn.prepare("SELECT exit FROM exit;")?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let raw_exit : Vec<u8> = row.get("exit")?;
		let exit :Exit = ciborium::from_reader(&raw_exit[..])?;
		Ok(Some(exit))
	}
	else {
		Ok(None)
	}
}
