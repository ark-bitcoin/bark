use anyhow::Context;
use futures::StreamExt;
use tokio::time::Instant;
use tokio_postgres::types::Type;

use bitcoin::consensus;
use bitcoin::secp256k1::{PublicKey, Parity};

use bitcoin_ext::rpc::{BitcoinRpcClient, BitcoinRpcExt};

use ark::vtxo::Full;
use ark::vtxo::raw::RawVtxo;
use ark::vtxo::policy::{ExpiryVtxoPolicy, ServerVtxoPolicy};
use ark::{ServerVtxo, musig};
use ark::encode::ProtocolEncoding;

use crate::database::Db;

const NOARG: &[&bool] = &[];

/// Fix board expiry VTXOs that were created with an incorrect internal key.
///
/// A bug in `BoardBuilder::build_internal_unsigned_vtxos` used only the
/// user pubkey as the internal key for the expiry policy, instead of the
/// combined (user + server) musig key. This made the resulting board
/// outputs unsweepable by the server.
///
/// Board expiry VTXOs are identified by `anchor_point = vtxo_id`.
///
/// For each candidate we compare the VTXO's expected txout against the
/// actual funding tx output. If they differ the bug is present and we
/// patch the internal key to the correct combined key.
pub async fn run(db: &Db, bitcoind: &BitcoinRpcClient) -> anyhow::Result<u64> {
	let reader = db.get_conn().await.context("reader connection")?;
	let writer = db.get_conn().await.context("writer connection")?;

	let total: i64 = reader.query_one(
		"SELECT COUNT(*) FROM vtxo WHERE anchor_point = vtxo_id",
		&[],
	).await.context("counting board expiry vtxos")?.get(0);

	if total == 0 {
		eprintln!("fix_board_expiry_policy: no board expiry vtxos found");
		return Ok(0);
	}

	eprintln!("fix_board_expiry_policy: checking {} board expiry vtxos", total);

	let select = reader.prepare(
		"SELECT id, vtxo_id, vtxo FROM vtxo WHERE anchor_point = vtxo_id",
	).await.context("preparing select")?;

	let update = writer.prepare_typed(
		"UPDATE vtxo \
		 SET vtxo = $2, \
		     policy = $3, \
		     updated_at = NOW() \
		 WHERE id = $1",
		&[Type::INT8, Type::BYTEA, Type::BYTEA],
	).await.context("preparing update")?;

	let rows = reader.query_raw(&select, NOARG).await
		.context("selecting board expiry vtxos")?;
	tokio::pin! { rows };

	let mut fixed: u64 = 0;
	let mut skipped: u64 = 0;
	let mut last_log = Instant::now();

	while let Some(row) = rows.next().await {
		let row = row.context("reading vtxo row")?;
		let id: i64 = row.get("id");
		let vtxo_id: &str = row.get("vtxo_id");
		let vtxo_bytes: &[u8] = row.get("vtxo");

		let vtxo = ServerVtxo::<Full>::deserialize(vtxo_bytes)
			.with_context(|| format!("failed to deserialize vtxo id={}", id))?;

		// Fetch the funding tx from bitcoind.
		let anchor = vtxo.chain_anchor();
		let tx_info = bitcoind.custom_get_raw_transaction_info(anchor.txid, None)
			.with_context(|| format!("failed to fetch funding tx for vtxo id={}", id))?;
		let tx_info = match tx_info {
			Some(info) => info,
			None => {
				eprintln!("fix_board_expiry_policy: funding tx {} not found for vtxo id={}, skipping",
					anchor.txid, id);
				skipped += 1;
				continue;
			}
		};
		let funding_tx: bitcoin::Transaction = consensus::deserialize(&tx_info.hex)
			.with_context(|| format!("failed to deserialize funding tx for vtxo id={}", id))?;

		let funding_txout = &funding_tx.output[anchor.vout as usize];

		// If the VTXO's txout already matches the funding tx, nothing to fix.
		if vtxo.txout() == *funding_txout {
			skipped += 1;
			continue;
		}

		// Extract the buggy internal key from the expiry policy.
		let internal_key = match vtxo.policy() {
			ServerVtxoPolicy::Expiry(ExpiryVtxoPolicy { internal_key }) => *internal_key,
			other => {
				eprintln!(
					"fix_board_expiry_policy: vtxo id={} has unexpected policy {:?}, skipping",
					id, other.policy_type(),
				);
				skipped += 1;
				continue;
			}
		};

		// The buggy internal key is user_pubkey.x_only(). Recover it as a full
		// pubkey (parity is irrelevant for musig key aggregation) and compute
		// the correct combined key.
		let user_pubkey = PublicKey::from_x_only_public_key(internal_key, Parity::Even);
		let combined_pubkey = musig::combine_keys([user_pubkey, vtxo.server_pubkey()])
			.x_only_public_key().0;

		// Deserialize as RawVtxo, fix the policy, and re-serialize.
		let mut raw = RawVtxo::deserialize(vtxo_bytes)
			.with_context(|| format!("failed to deserialize raw vtxo id={}", id))?;
		raw.policy = ServerVtxoPolicy::new_expiry(combined_pubkey);
		raw.amount = funding_txout.value;

		let new_policy_bytes = raw.policy.serialize();
		let new_vtxo_bytes = raw.serialize();

		// Verify the patched VTXO's txout matches the funding tx.
		let patched = ServerVtxo::<Full>::deserialize(&new_vtxo_bytes)
			.with_context(|| format!("patched vtxo failed to deserialize for id={}", id))?;
		if patched.txout() != *funding_txout {
			eprintln!(
				"fix_board_expiry_policy: patched vtxo id={} still doesn't match funding tx output, skipping",
				id,
			);
			skipped += 1;
			continue;
		}

		eprintln!("fix_board_expiry_policy: fixing vtxo id={} vtxo_id={}", id, vtxo_id);

		writer.execute(
			&update,
			&[&id, &new_vtxo_bytes.as_slice(), &new_policy_bytes.as_slice()],
		).await
			.with_context(|| format!("failed to update vtxo id={}", id))?;

		fixed += 1;

		if last_log.elapsed() >= std::time::Duration::from_secs(1) {
			last_log = Instant::now();
		}
	}

	eprintln!("fix_board_expiry_policy: done — fixed {}, skipped {}", fixed, skipped);
	Ok(fixed)
}
