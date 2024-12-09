use std::{path::PathBuf, str::FromStr};
use anyhow::Context;
use bitcoin::{bip32::Fingerprint, Amount, Network};
use rusqlite::{Connection, named_params, Transaction};
use crate::{exit::Exit, ReadOnlyConfig, Config, Vtxo, VtxoId, VtxoState};

pub (crate) fn store_config(
	conn: &Connection,
	pub_cfg: &Config,
	prv_cfg: &ReadOnlyConfig,
) -> anyhow::Result<()> {
	// Store the ftxo
	let query = 
		"INSERT INTO config 
			(id, network, fingerprint, asp_address, esplora_address, bitcoind_address, 
			bitcoind_cookiefile, bitcoind_user, bitcoind_pass, vtxo_refresh_threshold) 
		VALUES 
			(1, :network, :fingerprint, :asp_address, :esplora_address, :bitcoind_address, 
			:bitcoind_cookiefile, :bitcoind_user, :bitcoind_pass, :vtxo_refresh_threshold)
		ON CONFLICT (id)	
		DO UPDATE SET
			network = :network,
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
		":network": pub_cfg.network.to_string(),
		":fingerprint": prv_cfg.fingerprint.to_string(),
		":asp_address": pub_cfg.asp_address,
		":esplora_address": pub_cfg.esplora_address,
		":bitcoind_address": pub_cfg.bitcoind_address,
		":bitcoind_cookiefile": pub_cfg.bitcoind_cookiefile
			.clone().and_then(|f| f.to_str().map(String::from)),
		":bitcoind_user": pub_cfg.bitcoind_user,
		":bitcoind_pass": pub_cfg.bitcoind_pass,
		":vtxo_refresh_threshold": pub_cfg.vtxo_refresh_threshold,
	})?;

	Ok(())
}

pub (crate) fn fetch_config(conn: &Connection) -> anyhow::Result<Option<(Config, ReadOnlyConfig)>> {
	let query = "SELECT * FROM config";
	let mut statement = conn.prepare(query)?;
	let mut rows = statement.query([])?;

	if let Some(row) = rows.next()? {
		let network: String = row.get("network")?;
		let fingerprint: String = row.get("fingerprint")?;

		let bitcoind_cookiefile_opt: Option<String> = row.get("bitcoind_cookiefile")?;
		let bitcoind_cookiefile = if let Some (bitcoind_cookiefile) = bitcoind_cookiefile_opt {
			Some(PathBuf::try_from(bitcoind_cookiefile)?)
		} else {
			None
		};

		Ok(Some(
			(Config {
				network: Network::from_str(&network).context("invalid network")?,
				asp_address: row.get("asp_address")?,
				esplora_address: row.get("esplora_address")?,
				bitcoind_address: row.get("bitcoind_address")?,
				bitcoind_cookiefile: bitcoind_cookiefile,
				bitcoind_user: row.get("bitcoind_user")?,
				bitcoind_pass: row.get("bitcoind_pass")?,
				vtxo_refresh_threshold: row.get("vtxo_refresh_threshold")?,
			}, 
			ReadOnlyConfig {
				fingerprint: Fingerprint::from_str(&fingerprint).context("invalid fingerprint")?,
			}),
		))
	} else {
		Ok(None)
	}
}

pub fn store_vtxo_with_initial_state(
	tx: &Transaction,
	vtxo: &Vtxo,
	state: VtxoState
) -> anyhow::Result<()> {
	// Store the ftxo
	let q1 = 
		"INSERT INTO vtxo (id, expiry_height, amount_sat, raw_vtxo) 
		VALUES (:vtxo_id, :expiry_height, :amount_sat, :raw_vtxo);";
	let mut statement = tx.prepare(q1)?;
	statement.execute(named_params! {
		":vtxo_id" : vtxo.id().to_string(),
		":expiry_height": vtxo.spec().expiry_height,
		":amount_sat": vtxo.amount().to_sat(),
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
