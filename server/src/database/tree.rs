use std::collections::HashSet;

use anyhow::{Context, bail};

use bitcoin::{Transaction, Txid};
use tokio_postgres::GenericClient;

use ark::{ProtocolEncoding, ServerVtxo, VtxoId};
use ark::vtxo::{Bare, Full};

use super::model::{SpendState, VirtualTransaction};

// -- Update structs --

struct OorSpendUpdate {
	vtxo_id: VtxoId,
	txid: Txid,
}

struct RoundSpendUpdate {
	vtxo_id: VtxoId,
	round_id: i64,
}

struct OffboardSpendUpdate {
	vtxo_id: VtxoId,
	offboard_txid: Txid,
	forfeit_txid: Txid,
}

struct RoundForfeitUpdate {
	vtxo_id: VtxoId,
	txid: Txid,
}

struct UndoRoundUpdate {
	round_id: i64,
}

// -- Internal types --

/// Pre-built column arrays for a batched VTXO INSERT using UNNEST.
///
/// Each field is a parallel array — index `i` across all fields describes
/// a single VTXO row. The builder methods serialize VTXOs eagerly so that
/// `execute_vtxo_tree_update` can pass the arrays directly to one INSERT
/// query regardless of the mix of spendable, unclaimed, and oor-spent VTXOs.
struct VtxoInserts {
	vtxo_ids: Vec<String>,
	vtxo_txids: Vec<String>,
	data: Vec<Vec<u8>>,
	expiry: Vec<i32>,
	exit_deltas: Vec<i32>,
	policy_types: Vec<String>,
	policies: Vec<Vec<u8>>,
	server_pubkeys: Vec<String>,
	amounts: Vec<i64>,
	anchor_points: Vec<String>,
	spend_states: Vec<String>,
	oor_spent_txids: Vec<Option<String>>,
}

impl VtxoInserts {
	fn new() -> Self {
		VtxoInserts {
			vtxo_ids: Vec::new(),
			vtxo_txids: Vec::new(),
			data: Vec::new(),
			expiry: Vec::new(),
			exit_deltas: Vec::new(),
			policy_types: Vec::new(),
			policies: Vec::new(),
			server_pubkeys: Vec::new(),
			amounts: Vec::new(),
			anchor_points: Vec::new(),
			spend_states: Vec::new(),
			oor_spent_txids: Vec::new(),
		}
	}

	fn push_vtxo(&mut self, vtxo: &ServerVtxo<Full>, spend_state: SpendState, oor_spent_txid: Option<Txid>) {
		self.vtxo_ids.push(vtxo.id().to_string());
		self.vtxo_txids.push(vtxo.point().txid.to_string());
		self.data.push(vtxo.serialize());
		self.expiry.push(vtxo.expiry_height() as i32);
		self.exit_deltas.push(vtxo.exit_delta() as i32);
		self.policy_types.push(vtxo.policy_type().to_string());
		self.policies.push(vtxo.policy().serialize());
		self.server_pubkeys.push(vtxo.server_pubkey().to_string());
		self.amounts.push(vtxo.amount().to_sat() as i64);
		self.anchor_points.push(vtxo.chain_anchor().to_string());
		self.spend_states.push(spend_state.as_str().to_string());
		self.oor_spent_txids.push(oor_spent_txid.map(|t| t.to_string()));
	}

	fn push_bare_vtxo(&mut self, vtxo: &ServerVtxo<Bare>, spend_state: SpendState, oor_spent_txid: Option<Txid>) {
		self.vtxo_ids.push(vtxo.id().to_string());
		self.vtxo_txids.push(vtxo.point().txid.to_string());
		// Bare vtxos don't carry genesis data, store empty bytes.
		self.data.push(Vec::new());
		self.expiry.push(vtxo.expiry_height() as i32);
		self.exit_deltas.push(vtxo.exit_delta() as i32);
		self.policy_types.push(vtxo.policy_type().to_string());
		self.policies.push(vtxo.policy().serialize());
		self.server_pubkeys.push(vtxo.server_pubkey().to_string());
		self.amounts.push(vtxo.amount().to_sat() as i64);
		self.anchor_points.push(vtxo.chain_anchor().to_string());
		self.spend_states.push(spend_state.as_str().to_string());
		self.oor_spent_txids.push(oor_spent_txid.map(|t| t.to_string()));
	}

	fn push_spendable(&mut self, vtxo: &ServerVtxo<Full>) {
		self.push_vtxo(vtxo, SpendState::Spendable, None);
	}

	fn push_bare_spendable(&mut self, vtxo: &ServerVtxo<Bare>) {
		self.push_bare_vtxo(vtxo, SpendState::Spendable, None);
	}

	fn push_unclaimed(&mut self, vtxo: &ServerVtxo<Full>) {
		self.push_vtxo(vtxo, SpendState::Unclaimed, None);
	}

	fn push_oor_spent(&mut self, vtxo: &ServerVtxo<Full>, oor_spent_txid: Txid) {
		self.push_vtxo(vtxo, SpendState::Spent, Some(oor_spent_txid));
	}

	fn is_empty(&self) -> bool {
		self.vtxo_ids.is_empty()
	}
}

struct VtxoUpdates {
	oor_spends: Vec<OorSpendUpdate>,
	round_spends: Vec<RoundSpendUpdate>,
	offboard_spends: Vec<OffboardSpendUpdate>,
	round_forfeits: Vec<RoundForfeitUpdate>,
	round_unspends: Vec<UndoRoundUpdate>,
	claims: Vec<VtxoId>,
}

impl VtxoUpdates {
	fn new() -> Self {
		VtxoUpdates {
			oor_spends: Vec::new(),
			round_spends: Vec::new(),
			offboard_spends: Vec::new(),
			round_forfeits: Vec::new(),
			round_unspends: Vec::new(),
			claims: Vec::new(),
		}
	}

}

/// A batch update to the virtual transaction tree.
///
/// Execution order:
/// 1. Virtual tx upserts
/// 2. VTXO inserts
/// 3. VTXO updates
///
/// Idempotent: applying the exact same update twice succeeds.
/// Any different conflict bails.
pub struct VtxoTreeUpdate {
	tx_inserts: Vec<VirtualTransaction<'static>>,
	vtxo_inserts: VtxoInserts,
	vtxo_updates: VtxoUpdates,
}

impl VtxoTreeUpdate {
	pub fn new() -> Self {
		VtxoTreeUpdate {
			tx_inserts: Vec::new(),
			vtxo_inserts: VtxoInserts::new(),
			vtxo_updates: VtxoUpdates::new(),
		}
	}

	// -- virtual tx upserts --
	//
	// All virtual tx upserts are idempotent. Inserting the same txid twice
	// will update signed_tx if it was previously NULL. Never fails on conflict.

	/// Upsert a signed funding transaction.
	pub fn upsert_funding_tx(mut self, tx: &Transaction) -> Self {
		self.tx_inserts.push(VirtualTransaction::new_signed_owned(tx.clone()).as_funding());
		self
	}

	/// Upsert an unsigned funding transaction (txid only, no signed bytes).
	pub fn upsert_unsigned_funding_tx(mut self, txid: Txid) -> Self {
		self.tx_inserts.push(VirtualTransaction::new_unsigned(txid).as_funding());
		self
	}

	/// Upsert unsigned virtual transactions (txids only).
	pub fn upsert_unsigned_tx(mut self, txids: impl IntoIterator<Item = Txid>) -> Self {
		self.tx_inserts.extend(txids.into_iter().map(VirtualTransaction::new_unsigned));
		self
	}

	/// Upsert virtual transactions with their signed bytes.
	/// If the txid already exists with signed_tx = NULL, the signed bytes
	/// are filled in. If signed bytes already exist, they are kept.
	pub fn upsert_signed_tx(mut self, txs: impl IntoIterator<Item = Transaction>) -> Self {
		self.tx_inserts.extend(txs.into_iter().map(VirtualTransaction::new_signed_owned));
		self
	}

	/// Upsert pre-built virtual transactions.
	pub fn upsert_virtual_txs(mut self, vtxs: impl IntoIterator<Item = VirtualTransaction<'static>>) -> Self {
		self.tx_inserts.extend(vtxs);
		self
	}

	// -- vtxo inserts --
	//
	// Spendable/unclaimed/bare inserts are silent on conflict: re-inserting
	// the same vtxo_id is a no-op. `insert_oor_spent_vtxos` is stricter —
	// it bails if an existing row has a different `oor_spent_txid`, so that
	// a second call trying to record a conflicting OOR spend cannot be
	// silently deduped into authorizing a double-spend.

	/// Insert vtxos with `spend_state = 'spendable'`.
	pub fn insert_spendable_vtxos(
		mut self,
		vtxos: impl IntoIterator<Item = ServerVtxo<Full>>,
	) -> Self {
		for vtxo in vtxos {
			self.vtxo_inserts.push_spendable(&vtxo);
		}
		self
	}

	/// Insert vtxos with `spend_state = 'unclaimed'`.
	pub fn insert_unclaimed_vtxos(
		mut self,
		vtxos: impl IntoIterator<Item = ServerVtxo<Full>>,
	) -> Self {
		for vtxo in vtxos {
			self.vtxo_inserts.push_unclaimed(&vtxo);
		}
		self
	}

	/// Insert vtxos with `spend_state = 'spent'` and `oor_spent_txid` set.
	///
	/// Idempotent: succeeds if the row already exists with the same
	/// `oor_spent_txid`. Bails if it exists with a different txid (or with
	/// no `oor_spent_txid` set at all), to prevent silently authorizing a
	/// second OOR tx spending the same vtxo.
	pub fn insert_oor_spent_vtxos(
		mut self,
		vtxos: impl IntoIterator<Item = (ServerVtxo<Full>, Txid)>,
	) -> Self {
		for (vtxo, txid) in vtxos {
			self.vtxo_inserts.push_oor_spent(&vtxo, txid);
		}
		self
	}

	/// Insert bare vtxos with `spend_state = 'spendable'`.
	/// Bare vtxos don't carry genesis data so the vtxo column is empty.
	pub fn insert_spendable_bare_vtxos<V: std::borrow::Borrow<ServerVtxo<Bare>>>(
		mut self,
		vtxos: impl IntoIterator<Item = V>,
	) -> Self {
		for vtxo in vtxos {
			self.vtxo_inserts.push_bare_spendable(vtxo.borrow());
		}
		self
	}

	// -- vtxo updates --

	/// Mark spendable vtxos as spent out-of-round.
	///
	/// Idempotent: succeeds if the vtxo is already spent with the same txid.
	/// Fails if the vtxo doesn't exist, is already spent with a different
	/// txid, or is not in the 'spendable' state.
	pub fn mark_vtxos_oor_spent(
		mut self,
		pairs: impl IntoIterator<Item = (VtxoId, Txid)>,
	) -> Self {
		for (vtxo_id, txid) in pairs {
			self.vtxo_updates.oor_spends.push(OorSpendUpdate { vtxo_id, txid });
		}
		self
	}

	/// Mark spendable vtxos as spent in a round.
	///
	/// Idempotent: succeeds if the vtxo is already spent in the same round.
	/// Fails if the vtxo doesn't exist, is already spent in a different
	/// round, or is not in the 'spendable' state.
	pub fn mark_vtxos_round_spent(
		mut self,
		pairs: impl IntoIterator<Item = (VtxoId, i64)>,
	) -> Self {
		for (vtxo_id, round_id) in pairs {
			self.vtxo_updates.round_spends.push(RoundSpendUpdate { vtxo_id, round_id });
		}
		self
	}

	/// Mark spendable vtxos as spent via offboard.
	///
	/// Mark spendable vtxos as offboard-spent with their forfeit txid.
	///
	/// Sets both `offboarded_in = offboard_txid` and
	/// `oor_spent_txid = forfeit_txid` in a single update.
	///
	/// Idempotent: succeeds if already offboarded with the same txids.
	/// Fails if the vtxo doesn't exist, is already spent differently,
	/// or is not in the 'spendable' state.
	pub fn mark_vtxos_offboard_spent(
		mut self,
		triples: impl IntoIterator<Item = (VtxoId, Txid, Txid)>,
	) -> Self {
		for (vtxo_id, offboard_txid, forfeit_txid) in triples {
			self.vtxo_updates.offboard_spends.push(
				OffboardSpendUpdate { vtxo_id, offboard_txid, forfeit_txid },
			);
		}
		self
	}

	/// Record the forfeit txid on vtxos that were spent in a round.
	///
	/// Idempotent: succeeds if oor_spent_txid already matches.
	/// Fails if the vtxo is not round-spent, or already has a different
	/// oor_spent_txid.
	pub fn mark_vtxos_round_forfeited(
		mut self,
		pairs: impl IntoIterator<Item = (VtxoId, Txid)>,
	) -> Self {
		for (vtxo_id, txid) in pairs {
			self.vtxo_updates.round_forfeits.push(RoundForfeitUpdate { vtxo_id, txid });
		}
		self
	}

	/// Undo a round spend: set vtxos spent in the given round back to spendable.
	///
	/// Clears `spent_in_round` and `oor_spent_txid` (which may have been set
	/// by a subsequent forfeit recording) and resets `spend_state` to
	/// `'spendable'`.
	///
	/// Idempotent: if no vtxos match the round, nothing happens.
	pub fn undo_round(mut self, round_id: i64) -> Self {
		self.vtxo_updates.round_unspends.push(UndoRoundUpdate { round_id });
		self
	}

	/// Transition unclaimed vtxos to spendable.
	///
	/// Always idempotent: succeeds even if already claimed. Vtxos that
	/// are not in the 'unclaimed' state are silently skipped.
	pub fn mark_vtxos_claimed(
		mut self,
		ids: impl IntoIterator<Item = VtxoId>,
	) -> Self {
		self.vtxo_updates.claims.extend(ids);
		self
	}
}

// -- Execution --

/// Execute a [VtxoTreeUpdate] within a database transaction.
///
/// Execution order:
/// 1. Upsert virtual transactions
/// 2. Insert VTXOs (with ON CONFLICT DO NOTHING)
/// 3. Update existing VTXOs (mark spent, forfeited, claimed)
pub async fn execute_vtxo_tree_update(
	tx: &tokio_postgres::Transaction<'_>,
	update: VtxoTreeUpdate,
) -> anyhow::Result<()> {
	debug_assert!(validate(&update).is_ok(), "{}", validate(&update).unwrap_err());

	upsert_virtual_transactions(tx, &update.tx_inserts).await?;
	insert_vtxos(tx, &update.vtxo_inserts).await?;
	apply_vtxo_updates(tx, &update.vtxo_updates).await?;

	Ok(())
}

async fn upsert_virtual_transactions<T: GenericClient>(
	client: &T,
	txs: &[VirtualTransaction<'_>],
) -> anyhow::Result<()> {
	if txs.is_empty() { return Ok(()) }
	let mut txids = Vec::with_capacity(txs.len());
	let mut signed_txs: Vec<Option<Vec<u8>>> = Vec::with_capacity(txs.len());
	let mut is_funding = Vec::with_capacity(txs.len());
	for vtx in txs {
		txids.push(vtx.txid.to_string());
		signed_txs.push(vtx.signed_tx().map(bitcoin::consensus::serialize));
		is_funding.push(vtx.is_funding);
	}
	client.execute("
		INSERT INTO virtual_transaction
			(txid, signed_tx, is_funding, created_at, updated_at)
		SELECT txid, signed_tx, is_funding, NOW(), NOW()
		FROM UNNEST($1::text[], $2::bytea[], $3::bool[])
			AS u(txid, signed_tx, is_funding)
		ON CONFLICT (txid) DO UPDATE SET
			signed_tx = COALESCE(virtual_transaction.signed_tx, EXCLUDED.signed_tx),
			updated_at = NOW()
	", &[&txids, &signed_txs, &is_funding]).await
		.context("failed to upsert virtual transactions")?;
	Ok(())
}

async fn insert_vtxos<T: GenericClient>(
	client: &T,
	vi: &VtxoInserts,
) -> anyhow::Result<()> {
	if vi.is_empty() { return Ok(()) }
	// ON CONFLICT DO NOTHING just continues if the vtxo already exists. For
	// rows inserted via `insert_oor_spent_vtxos`, we then validate that the
	// existing row's oor_spent_txid actually matches — otherwise the insert
	// would silently authorize a double-spend.
	client.execute("
		INSERT INTO vtxo (
			vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
			server_pubkey, amount, anchor_point,
			spend_state, oor_spent_txid, created_at, updated_at
		) VALUES (
			UNNEST($1::text[]), UNNEST($2::text[]), UNNEST($3::bytea[]),
			UNNEST($4::int4[]), UNNEST($5::int4[]), UNNEST($6::text[]),
			UNNEST($7::bytea[]), UNNEST($8::text[]), UNNEST($9::int8[]),
			UNNEST($10::text[]), UNNEST($11::text[])::spend_state,
			UNNEST($12::text[]), NOW(), NOW()
		)
		ON CONFLICT DO NOTHING
	", &[
		&vi.vtxo_ids, &vi.vtxo_txids, &vi.data, &vi.expiry,
		&vi.exit_deltas, &vi.policy_types, &vi.policies, &vi.server_pubkeys,
		&vi.amounts, &vi.anchor_points, &vi.spend_states, &vi.oor_spent_txids,
	]).await.context("failed to insert VTXOs")?;

	let bad = client.query_opt("
		SELECT u.vtxo_id
		FROM UNNEST($1::text[], $2::text[]) AS u(vtxo_id, expected_txid)
		JOIN vtxo v ON v.vtxo_id = u.vtxo_id
		WHERE u.expected_txid IS NOT NULL
			AND v.oor_spent_txid IS DISTINCT FROM u.expected_txid
		LIMIT 1
	", &[&vi.vtxo_ids, &vi.oor_spent_txids])
		.await.context("failed to verify oor-spent inserts")?;
	if let Some(row) = bad {
		let vtxo_id: &str = row.get("vtxo_id");
		bail!("vtxo {} is already spent", vtxo_id);
	}
	Ok(())
}

async fn apply_vtxo_updates<T: GenericClient>(
	client: &T,
	vu: &VtxoUpdates,
) -> anyhow::Result<()> {
	do_oor_spend_updates(client, &vu.oor_spends).await?;
	do_round_spend_updates(client, &vu.round_spends).await?;
	do_offboard_spend_updates(client, &vu.offboard_spends).await?;
	do_round_forfeit_updates(client, &vu.round_forfeits).await?;
	do_undo_round_updates(client, &vu.round_unspends).await?;
	do_claim_updates(client, &vu.claims).await?;
	Ok(())
}

// -- Individual update functions --

/// Idempotent: succeeds if already spent with the same oor_spent_txid.
async fn do_oor_spend_updates<T: GenericClient>(
	client: &T,
	spends: &[OorSpendUpdate],
) -> anyhow::Result<()> {
	if spends.is_empty() { return Ok(()) }
	let ids: Vec<String> = spends.iter().map(|s| s.vtxo_id.to_string()).collect();
	let txids: Vec<String> = spends.iter().map(|s| s.txid.to_string()).collect();
	let rows = client.execute("
		UPDATE vtxo SET spend_state = 'spent', oor_spent_txid = u.txid, updated_at = NOW()
		FROM UNNEST($1::text[], $2::text[]) AS u(vtxo_id, txid)
		WHERE vtxo.vtxo_id = u.vtxo_id
		AND (vtxo.spend_state = 'spendable'
			OR (vtxo.spend_state = 'spent' AND vtxo.oor_spent_txid = u.txid))
	", &[&ids, &txids]).await.context("failed to mark VTXOs as oor-spent")?;
	if rows != spends.len() as u64 {
		// Find the first vtxo that wasn't spendable and doesn't match our txid
		let bad = client.query_one("
			SELECT u.vtxo_id, v.spend_state::text, v.oor_spent_txid
			FROM UNNEST($1::text[], $2::text[]) AS u(vtxo_id, txid)
			LEFT JOIN vtxo v ON v.vtxo_id = u.vtxo_id
			WHERE v.vtxo_id IS NULL
				OR (v.spend_state != 'spendable'
					AND NOT (v.spend_state = 'spent' AND v.oor_spent_txid = u.txid))
			LIMIT 1
		", &[&ids, &txids]).await.context("failed to find bad vtxo")?;
		let vtxo_id: &str = bad.get("vtxo_id");
		bail!("vtxo doesn't exist or is unspendable: {}", vtxo_id);
	}
	Ok(())
}

/// Idempotent: succeeds if already spent in the same round.
async fn do_round_spend_updates<T: GenericClient>(
	client: &T,
	spends: &[RoundSpendUpdate],
) -> anyhow::Result<()> {
	if spends.is_empty() { return Ok(()) }
	let ids: Vec<String> = spends.iter().map(|s| s.vtxo_id.to_string()).collect();
	let round_ids: Vec<i64> = spends.iter().map(|s| s.round_id).collect();
	let rows = client.execute("
		UPDATE vtxo SET spend_state = 'spent', spent_in_round = u.round_id, updated_at = NOW()
		FROM UNNEST($1::text[], $2::int8[]) AS u(vtxo_id, round_id)
		WHERE vtxo.vtxo_id = u.vtxo_id
		AND (vtxo.spend_state = 'spendable'
			OR (vtxo.spend_state = 'spent' AND vtxo.spent_in_round = u.round_id))
	", &[&ids, &round_ids]).await.context("failed to mark VTXOs as round-spent")?;
	if rows != spends.len() as u64 {
		let bad = client.query_one("
			SELECT u.vtxo_id, v.spend_state::text, v.spent_in_round
			FROM UNNEST($1::text[], $2::int8[]) AS u(vtxo_id, round_id)
			LEFT JOIN vtxo v ON v.vtxo_id = u.vtxo_id
			WHERE v.vtxo_id IS NULL
				OR (v.spend_state != 'spendable'
					AND NOT (v.spend_state = 'spent' AND v.spent_in_round = u.round_id))
			LIMIT 1
		", &[&ids, &round_ids]).await.context("failed to find bad vtxo")?;
		let vtxo_id: &str = bad.get("vtxo_id");
		bail!("vtxo doesn't exist or is unspendable: {}", vtxo_id);
	}
	Ok(())
}

/// Marks spendable vtxos as spent via offboard and records the forfeit
/// txid in a single update.
///
/// Idempotent: succeeds if already offboarded with the same txids.
async fn do_offboard_spend_updates<T: GenericClient>(
	client: &T,
	spends: &[OffboardSpendUpdate],
) -> anyhow::Result<()> {
	if spends.is_empty() { return Ok(()) }
	let ids: Vec<String> = spends.iter().map(|s| s.vtxo_id.to_string()).collect();
	let offboard_txids: Vec<String> = spends.iter().map(|s| s.offboard_txid.to_string()).collect();
	let forfeit_txids: Vec<String> = spends.iter().map(|s| s.forfeit_txid.to_string()).collect();
	let rows = client.execute("
		UPDATE vtxo SET
			spend_state = 'spent',
			offboarded_in = u.offboard_txid,
			oor_spent_txid = u.forfeit_txid,
			updated_at = NOW()
		FROM UNNEST($1::text[], $2::text[], $3::text[])
			AS u(vtxo_id, offboard_txid, forfeit_txid)
		WHERE vtxo.vtxo_id = u.vtxo_id
		AND (vtxo.spend_state = 'spendable'
			OR (vtxo.spend_state = 'spent'
				AND vtxo.offboarded_in = u.offboard_txid
				AND vtxo.oor_spent_txid = u.forfeit_txid))
	", &[&ids, &offboard_txids, &forfeit_txids])
		.await.context("failed to mark VTXOs as offboard-spent")?;
	if rows != spends.len() as u64 {
		let bad = client.query_one("
			SELECT u.vtxo_id
			FROM UNNEST($1::text[], $2::text[], $3::text[])
				AS u(vtxo_id, offboard_txid, forfeit_txid)
			LEFT JOIN vtxo v ON v.vtxo_id = u.vtxo_id
			WHERE v.vtxo_id IS NULL
				OR (v.spend_state != 'spendable'
					AND NOT (v.spend_state = 'spent'
						AND v.offboarded_in = u.offboard_txid
						AND v.oor_spent_txid = u.forfeit_txid))
			LIMIT 1
		", &[&ids, &offboard_txids, &forfeit_txids])
			.await.context("failed to find bad vtxo")?;
		let vtxo_id: &str = bad.get("vtxo_id");
		bail!("vtxo doesn't exist or is unspendable: {}", vtxo_id);
	}
	Ok(())
}

/// Idempotent: succeeds if oor_spent_txid already matches.
async fn do_round_forfeit_updates<T: GenericClient>(
	client: &T,
	forfeits: &[RoundForfeitUpdate],
) -> anyhow::Result<()> {
	if forfeits.is_empty() { return Ok(()) }
	let ids: Vec<String> = forfeits.iter().map(|f| f.vtxo_id.to_string()).collect();
	let txids: Vec<String> = forfeits.iter().map(|f| f.txid.to_string()).collect();
	let rows = client.execute("
		UPDATE vtxo SET oor_spent_txid = u.txid, updated_at = NOW()
		FROM UNNEST($1::text[], $2::text[]) AS u(vtxo_id, txid)
		WHERE vtxo.vtxo_id = u.vtxo_id
		AND vtxo.spend_state = 'spent'
		AND vtxo.spent_in_round IS NOT NULL
		AND (vtxo.oor_spent_txid IS NULL OR vtxo.oor_spent_txid = u.txid)
	", &[&ids, &txids]).await.context("failed to mark VTXOs as round-forfeited")?;
	if rows != forfeits.len() as u64 {
		let bad = client.query_one("
			SELECT u.vtxo_id, v.spend_state::text, v.spent_in_round, v.oor_spent_txid
			FROM UNNEST($1::text[], $2::text[]) AS u(vtxo_id, txid)
			LEFT JOIN vtxo v ON v.vtxo_id = u.vtxo_id
			WHERE v.vtxo_id IS NULL
				OR v.spend_state != 'spent'
				OR v.spent_in_round IS NULL
				OR (v.oor_spent_txid IS NOT NULL AND v.oor_spent_txid != u.txid)
			LIMIT 1
		", &[&ids, &txids]).await.context("failed to find bad vtxo")?;
		let vtxo_id: &str = bad.get("vtxo_id");
		bail!("vtxo not round-spent or already forfeited differently: {}", vtxo_id);
	}
	Ok(())
}

/// Undo a round spend: reset vtxos spent in the given rounds back to spendable.
/// Idempotent: if no vtxos match, nothing happens.
async fn do_undo_round_updates<T: GenericClient>(
	client: &T,
	unspends: &[UndoRoundUpdate],
) -> anyhow::Result<()> {
	if unspends.is_empty() { return Ok(()) }
	let round_ids: Vec<i64> = unspends.iter().map(|s| s.round_id).collect();
	client.execute("
		UPDATE vtxo
		SET spend_state = 'spendable', spent_in_round = NULL, oor_spent_txid = NULL, updated_at = NOW()
		WHERE spent_in_round = ANY($1::int8[])
	", &[&round_ids]).await.context("failed to undo round spend on VTXOs")?;
	Ok(())
}

/// Transitions unclaimed vtxos to spendable after the preimage is released.
/// Always idempotent: succeeds even if already claimed.
async fn do_claim_updates<T: GenericClient>(
	client: &T,
	claims: &[VtxoId],
) -> anyhow::Result<()> {
	if claims.is_empty() { return Ok(()) }
	let ids: Vec<String> = claims.iter().map(|id| id.to_string()).collect();
	client.execute("
		UPDATE vtxo SET spend_state = 'spendable', updated_at = NOW()
		WHERE vtxo_id = ANY($1::text[]) AND spend_state = 'unclaimed'
	", &[&ids]).await.context("failed to mark VTXOs as claimed")?;
	Ok(())
}

// -- Validation --

/// Validate the update for internal consistency (debug only).
fn validate(update: &VtxoTreeUpdate) -> anyhow::Result<()> {
	let mut seen_vtxo_ids = HashSet::new();
	for id in &update.vtxo_inserts.vtxo_ids {
		if !seen_vtxo_ids.insert(id.clone()) {
			bail!("duplicate vtxo id {} in vtxo_inserts", id);
		}
	}

	let vu = &update.vtxo_updates;
	let mut seen_update_ids = HashSet::new();
	let all_update_ids = vu.oor_spends.iter().map(|s| &s.vtxo_id)
		.chain(vu.round_spends.iter().map(|s| &s.vtxo_id))
		.chain(vu.offboard_spends.iter().map(|s| &s.vtxo_id))
		.chain(vu.round_forfeits.iter().map(|f| &f.vtxo_id))
		.chain(vu.claims.iter());
	for id in all_update_ids {
		if !seen_update_ids.insert(id) {
			bail!("duplicate vtxo id {} in vtxo updates", id);
		}
	}

	let mut seen_txids = HashSet::new();
	for vtx in &update.tx_inserts {
		if !seen_txids.insert(vtx.txid) {
			bail!("duplicate virtual tx txid {}", vtx.txid);
		}
	}

	Ok(())
}
