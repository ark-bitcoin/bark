//! Split `bark_vtxo.raw_vtxo` into a bare encoding plus a separate genesis blob, and
//! cache two genesis-derived summary fields used by [RefreshStrategy] so listings
//! and refresh selection don't have to load the (potentially tens-of-KB) exit
//! chain in memory.
//!
//! Backfill is a single forward pass: deserialize the existing full-encoded
//! `raw_vtxo`, write back `raw_bare`, `raw_genesis`, `exit_depth`, and
//! `exit_tx_weight`, then drop `raw_vtxo` and recreate `vtxo_view` to expose
//! the new columns (without `raw_genesis`, which only the hydration path
//! reads).
//!
//! Counterparty-risk checks (which inspect `past_arkoor_pubkeys`) are
//! infrequent and only run on a small refresh-candidate set, so we don't
//! cache that here — those checks load the full VTXO from disk on demand.

use anyhow::Context;
use rusqlite::{Transaction, params};

use ark::{ProtocolEncoding, Vtxo};
use ark::vtxo::Full;

use super::Migration;

pub struct Migration0029 {}

impl Migration for Migration0029 {
	fn name(&self) -> &str {
		"Split bark_vtxo.raw_vtxo into bare + genesis with cached refresh-strategy summaries"
	}

	fn to_version(&self) -> i64 { 29 }

	fn do_migration(&self, conn: &Transaction) -> anyhow::Result<()> {
		let add_column_stmts = [
			"ALTER TABLE bark_vtxo ADD COLUMN raw_bare BLOB",
			"ALTER TABLE bark_vtxo ADD COLUMN raw_genesis BLOB",
			"ALTER TABLE bark_vtxo ADD COLUMN exit_depth INTEGER",
			"ALTER TABLE bark_vtxo ADD COLUMN exit_tx_weight INTEGER",
		];
		for stmt in add_column_stmts {
			conn.execute(stmt, ()).with_context(|| {
				format!("failed to add bark_vtxo column: {stmt}")
			})?;
		}

		// Backfill: read every existing row, split it, write the new columns
		// back. Done in two phases (collect ids/blobs, then update) to avoid
		// holding a SELECT statement open across UPDATEs on the same table.
		let rows = {
			let mut stmt = conn.prepare(
				"SELECT id, raw_vtxo FROM bark_vtxo WHERE raw_vtxo IS NOT NULL",
			)?;
			let mapped = stmt.query_map((), |r| {
				let id: String = r.get(0)?;
				let raw: Vec<u8> = r.get(1)?;
				Ok((id, raw))
			})?;
			mapped.collect::<Result<Vec<_>, _>>()
				.context("failed to read pre-migration bark_vtxo rows")?
		};

		let mut update = conn.prepare(
			"UPDATE bark_vtxo
			SET raw_bare = ?1,
				raw_genesis = ?2,
				exit_depth = ?3,
				exit_tx_weight = ?4
			WHERE id = ?5",
		)?;
		for (id, raw) in rows {
			let vtxo = Vtxo::<Full>::deserialize(&raw).with_context(|| {
				format!("failed to deserialize raw_vtxo for id={id}")
			})?;

			let raw_bare = vtxo.to_bare().serialize();
			let raw_genesis = vtxo.serialize_genesis();
			let exit_depth = vtxo.exit_depth() as i64;
			let exit_tx_weight = exit_tx_weight_wu(&vtxo) as i64;

			update.execute(params![
				raw_bare,
				raw_genesis,
				exit_depth,
				exit_tx_weight,
				id,
			]).with_context(|| format!("failed to update bark_vtxo row id={id}"))?;
		}
		drop(update);

		// vtxo_view references raw_vtxo, so it has to go before we can drop
		// the column. We recreate it below with the new column list. The
		// new view intentionally omits raw_genesis — hydration queries
		// fetch that directly from bark_vtxo.
		conn.execute("DROP VIEW vtxo_view", ())
			.context("failed to drop vtxo_view")?;

		// Older code path is gone. We don't ever read raw_vtxo after this
		// migration commits, so drop the column. SQLite >= 3.35 supports it,
		// and libsqlite3-sys 0.28 ships 3.45.
		conn.execute("ALTER TABLE bark_vtxo DROP COLUMN raw_vtxo", ())
			.context("failed to drop bark_vtxo.raw_vtxo")?;

		conn.execute(
			"CREATE VIEW vtxo_view AS
			SELECT
				v.id,
				v.expiry_height,
				v.amount_sat,
				v.raw_bare,
				v.exit_depth,
				v.exit_tx_weight,
				v.created_at,
				vs.state,
				vs.state_kind,
				vs.last_updated_at
			FROM bark_vtxo as v
			JOIN most_recent_vtxo_state as vs
				ON v.id = vs.vtxo_id",
			(),
		).context("failed to recreate vtxo_view")?;

		Ok(())
	}
}

/// Sum of weight units across a VTXO's full unilateral exit transaction chain.
///
/// Mirrors the per-vtxo summation inside `bark::exit::progress::util::estimate_exit_cost`
/// (without the 2× CPFP fudge factor — the consumer applies that). Cached at insert time
/// so refresh-strategy "uneconomical to exit" checks don't have to hydrate genesis.
fn exit_tx_weight_wu(vtxo: &Vtxo<Full>) -> u64 {
	vtxo.transactions()
		.map(|t| t.tx.weight().to_wu())
		.sum::<u64>()
}

#[cfg(test)]
mod test {
	use super::*;

	use ark::vtxo::Bare;
	use bitcoin::Weight;
	use rusqlite::Connection;

	use super::super::MigrationContext;

	fn run_through_migration_28(conn: &mut Connection) {
		use super::super::{
			m0001_initial_version::Migration0001,
			m0002_config::Migration0002,
			m0003_payment_history::Migration0003,
			m0004_unregistered_board::Migration0004,
			m0005_lightning_receive::Migration0005,
			m0006_exit_rework::Migration0006,
			m0007_vtxo_refresh_expiry_threshold::Migration0007,
			m0008_fee_rate_implementation::Migration0008,
			m0009_add_movement_kind::Migration0009,
			m0010_remove_keychain::Migration0010,
			m0011_exit_ancestor_info::Migration0011,
			m0012_round::Migration0012,
			m0013_round_sync::Migration0013,
			m0014_drop_past_round_sync::Migration0014,
			m0015_optional_round_seq::Migration0015,
			m0016_config::Migration0016,
			m0017_great_state_cleanup::Migration0017,
			m0018_htlc_recv_cltv_delta::Migration0018,
			m0019_round_state::Migration0019,
			m0020_new_movements_api::Migration0020,
			m0021_fix_lightning_movements::Migration0021,
			m0022_unreleased::Migration0022,
			m0023_mailbox::Migration0023,
			m0024_server_pubkey::Migration0024,
			m0025_fees::Migration0025,
			m0026_pending_offboard::Migration0026,
			m0027_split_destination::Migration0027,
			m0028_mailbox_pubkey::Migration0028,
		};

		// Run the migrations framework but stop just before m0029.
		let ctx = MigrationContext::new();
		let tx = conn.transaction().unwrap();
		ctx.init_migrations(&tx).unwrap();
		tx.commit().unwrap();

		ctx.try_migration(conn, &Migration0001{}).unwrap();
		ctx.try_migration(conn, &Migration0002{}).unwrap();
		ctx.try_migration(conn, &Migration0003{}).unwrap();
		ctx.try_migration(conn, &Migration0004{}).unwrap();
		ctx.try_migration(conn, &Migration0005{}).unwrap();
		ctx.try_migration(conn, &Migration0006{}).unwrap();
		ctx.try_migration(conn, &Migration0007{}).unwrap();
		ctx.try_migration(conn, &Migration0008{}).unwrap();
		ctx.try_migration(conn, &Migration0009{}).unwrap();
		ctx.try_migration(conn, &Migration0010{}).unwrap();
		ctx.try_migration(conn, &Migration0011{}).unwrap();
		ctx.try_migration(conn, &Migration0012{}).unwrap();
		ctx.try_migration(conn, &Migration0013{}).unwrap();
		ctx.try_migration(conn, &Migration0014{}).unwrap();
		ctx.try_migration(conn, &Migration0015{}).unwrap();
		ctx.try_migration(conn, &Migration0016{}).unwrap();
		ctx.try_migration(conn, &Migration0017{}).unwrap();
		ctx.try_migration(conn, &Migration0018{}).unwrap();
		ctx.try_migration(conn, &Migration0019{}).unwrap();
		ctx.try_migration(conn, &Migration0020{}).unwrap();
		ctx.try_migration(conn, &Migration0021{}).unwrap();
		ctx.try_migration(conn, &Migration0022{}).unwrap();
		ctx.try_migration(conn, &Migration0023{}).unwrap();
		ctx.try_migration(conn, &Migration0024{}).unwrap();
		ctx.try_migration(conn, &Migration0025{}).unwrap();
		ctx.try_migration(conn, &Migration0026{}).unwrap();
		ctx.try_migration(conn, &Migration0027{}).unwrap();
		ctx.try_migration(conn, &Migration0028{}).unwrap();
	}

	#[test]
	fn test_migration_0029_preserves_vtxo_bytes() {
		let mut conn = Connection::open_in_memory().unwrap();
		run_through_migration_28(&mut conn);

		// Insert a couple of fixture VTXOs at version 28 (full-encoded raw_vtxo).
		let vectors = &*ark::test_util::vectors::VTXO_VECTORS;
		let fixtures = [
			("board", &vectors.board_vtxo),
			("arkoor_htlc", &vectors.arkoor_htlc_out_vtxo),
			("arkoor3", &vectors.arkoor3_vtxo),
		];
		for (label, vtxo) in fixtures {
			conn.execute(
				"INSERT INTO bark_vtxo (id, expiry_height, amount_sat, raw_vtxo)
				VALUES (?1, ?2, ?3, ?4)",
				params![
					vtxo.id().to_string(),
					vtxo.expiry_height(),
					vtxo.amount().to_sat(),
					vtxo.serialize(),
				],
			).unwrap_or_else(|e| panic!("insert {label}: {e}"));
		}

		// Now run the migration.
		let ctx = MigrationContext::new();
		ctx.try_migration(&mut conn, &Migration0029{}).unwrap();

		// For each fixture, read back the split columns + cached scalars and
		// confirm Bare + Genesis reassemble byte-identically and the cached
		// values match the live-computed values.
		for (label, vtxo) in fixtures {
			let row: (Vec<u8>, Vec<u8>, i64, i64) = conn.query_row(
				"SELECT raw_bare, raw_genesis, exit_depth, exit_tx_weight
				FROM bark_vtxo WHERE id = ?1",
				params![vtxo.id().to_string()],
				|r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
			).unwrap_or_else(|e| panic!("read {label}: {e}"));
			let (raw_bare, raw_genesis, exit_depth, exit_tx_weight) = row;

			let reassembled = Vtxo::<Full>::deserialize_with_genesis(
				&raw_bare[..], &raw_genesis[..],
			).expect("failed to reassemble VTXO");
			assert_eq!(reassembled.serialize(), vtxo.serialize(),
				"{label}: reassembled bytes differ from original");

			assert_eq!(exit_depth as u16, vtxo.exit_depth(), "{label}: exit_depth");
			assert_eq!(
				Weight::from_wu(exit_tx_weight as u64),
				Weight::from_wu(exit_tx_weight_wu(vtxo)),
				"{label}: exit_tx_weight",
			);
		}

		// raw_vtxo column is gone.
		let cols: Vec<String> = {
			let mut stmt = conn.prepare("PRAGMA table_info(bark_vtxo)").unwrap();
			let mapped = stmt.query_map((), |r| r.get::<_, String>(1)).unwrap();
			mapped.collect::<Result<_, _>>().unwrap()
		};
		assert!(!cols.iter().any(|c| c == "raw_vtxo"), "raw_vtxo should be dropped");
		for required in ["raw_bare", "raw_genesis", "exit_depth", "exit_tx_weight"] {
			assert!(cols.iter().any(|c| c == required), "missing column {required}");
		}
	}
}
