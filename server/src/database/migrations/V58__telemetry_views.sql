-- VTXO telemetry views. Polled by barking-bot's vtxo_replica_telemetry
-- and read directly from Grafana. Frontier-scoped via v_frontier_vtxos;
-- offboard-connector vtxos are filtered out everywhere: they are dust
-- plumbing outputs (structural connectors emitted alongside every
-- offboard-forfeit, ~330 sat, server-owned, no user value), and
-- counting them would roughly double n on any by-state breakdown and
-- inflate a "server-owned" ownership bucket that isn't real money.
--
-- Partial indexes at the top of this migration cover every WHERE
-- predicate these views use: the frontier hot-set, on-chain-spent
-- rows for the by-kind views, and the seed set for the conflict /
-- cascade recursive CTEs. vtxo_txid_ix (V25) carries the recursive
-- child.vtxo_txid = parent.oor_spent_txid join step. Still prefer the
-- read replica for expensive scans, but no longer bounded by
-- full-table sequential scans.


-- ---------------------------------------------------------------------
-- Idempotency header: drop every object this migration creates so the
-- file can be re-applied by hand while iterating (refinery already
-- refuses to re-run V57, but manual `psql < V57__...sql` should work
-- too). Ordered leaves-first so no CASCADE is needed; if you add a new
-- view/function, add its DROP here too. v_vtxo_conflicted_totals is
-- dropped even though this migration no longer creates it, because
-- earlier iterations did and it may linger in dev databases.
-- ---------------------------------------------------------------------

DROP VIEW IF EXISTS v_frontier_reconciliation;
DROP VIEW IF EXISTS v_frontier_ownership_totals;
DROP VIEW IF EXISTS v_vtxo_frontier_by_state_by_expiry;
DROP VIEW IF EXISTS v_vtxo_onchain_spent_by_kind_by_expiry;
DROP VIEW IF EXISTS v_vtxo_conflicted_by_expiry;
DROP VIEW IF EXISTS v_vtxo_frontier_by_expiry;
DROP VIEW IF EXISTS v_vtxo_onchain_spent_by_height;
DROP VIEW IF EXISTS v_unconfirmed_funding_txs;
DROP VIEW IF EXISTS v_funding_no_frontier_outputs;
DROP VIEW IF EXISTS v_cascade_roots;
DROP VIEW IF EXISTS v_vtxo_by_spend_state;
DROP VIEW IF EXISTS v_vtxo_by_onchain_spent_kind;
DROP VIEW IF EXISTS v_vtxo_conflicted_frontier_by_ownership;
DROP VIEW IF EXISTS v_vtxo_conflicted_frontier_totals;
DROP VIEW IF EXISTS v_vtxo_frontier_totals;
DROP FUNCTION IF EXISTS vtxo_late_sweeps(integer, integer);
DROP VIEW IF EXISTS v_vtxo_conflicted_totals;
DROP VIEW IF EXISTS v_conflicted_vtxos;
DROP VIEW IF EXISTS v_frontier_vtxos;
DROP VIEW IF EXISTS v_conflicted_txids;

DROP INDEX IF EXISTS vtxo_frontier_active_ix;
DROP INDEX IF EXISTS vtxo_onchain_spent_active_ix;
DROP INDEX IF EXISTS vtxo_conflict_seed_ix;
DROP INDEX IF EXISTS virtual_transaction_funding_ix;


-- ---------------------------------------------------------------------
-- Indexes. All partial: each is scoped to the exact predicate the
-- corresponding view filters on, so write overhead on vtxo is bounded
-- to state transitions that touch the covered subset (frontier
-- vtxos, on-chain-spent vtxos, and vtxos with both oor_spent_txid
-- and onchain_spent_txid set). The unconditional vtxo_txid_ix from
-- V25 carries the recursive OOR-descent (child.vtxo_txid =
-- parent.oor_spent_txid); the LATERAL rewrites below use it via a
-- nested loop.
-- ---------------------------------------------------------------------

-- Frontier hot-set. Serves v_frontier_vtxos and everything reading
-- from it: totals, by-expiry breakdowns, vtxo_late_sweeps, and the
-- seed of v_frontier_ownership_totals. Sorted by expiry so the
-- late-sweep range scan (expiry + margin <= chain_tip) is index-only.
CREATE INDEX vtxo_frontier_active_ix ON vtxo (expiry)
WHERE frontier_at IS NOT NULL
  AND onchain_spent_txid IS NULL
  AND spend_state <> 'offboard-connector';

-- On-chain-spent rows. Serves v_vtxo_by_onchain_spent_kind and its
-- by-expiry / by-height variants. onchain_spent_height as the key so
-- the by-height view can range-scan without a sort.
CREATE INDEX vtxo_onchain_spent_active_ix ON vtxo (onchain_spent_height)
WHERE onchain_spent_height IS NOT NULL
  AND spend_state <> 'offboard-connector';

-- Conflict seed: vtxos where a recorded OOR spend disagrees with the
-- on-chain spend. Serves the base case of v_conflicted_txids and
-- v_cascade_roots. oor_spent_txid as the key so the DISTINCT dedup
-- in the base CTE reads it index-only.
CREATE INDEX vtxo_conflict_seed_ix ON vtxo (oor_spent_txid)
WHERE onchain_spent_txid IS NOT NULL
  AND oor_spent_txid IS NOT NULL
  AND spend_state <> 'offboard-connector';

-- Funding txs. Serves v_unconfirmed_funding_txs and
-- v_funding_no_frontier_outputs, which both filter vt.is_funding
-- before joining. Partial on the boolean so the index only holds
-- funding rows.
CREATE INDEX virtual_transaction_funding_ix ON virtual_transaction (txid)
WHERE is_funding = true;

-- Refresh planner stats so the partial indexes above are picked up
-- on the very first query after the migration lands, rather than
-- waiting for autovacuum. Without this, the recursive CTEs may keep
-- their pre-index plans (hash join + Seq Scan) until autoanalyze
-- catches up.
ANALYZE vtxo;
ANALYZE virtual_transaction;


-- ---------------------------------------------------------------------
-- Base views.
-- ---------------------------------------------------------------------

-- Conflicted OOR-spend txids: txs recorded in oor_spent_txid (arkoor,
-- round-forfeit, or offboard-forfeit are the three writers) whose
-- input UTXO has already been spent on-chain by a competing tx (sweep
-- or exit), so the recorded OOR spend can never take effect. Walks
-- parent.oor_spent_txid -> child.vtxo_txid; in practice this follows
-- arkoor chains, since arkoor is the only writer whose tx also
-- creates vtxo rows (round/offboard-forfeit txs are seizure txs and
-- produce no children). Deduped by txid via UNION so multi-input
-- arkoor subtrees traverse exactly once.
CREATE VIEW v_conflicted_txids AS
WITH RECURSIVE conflicted(txid) AS (
    SELECT DISTINCT root.oor_spent_txid
    FROM vtxo root
    WHERE root.onchain_spent_txid IS NOT NULL
      AND root.oor_spent_txid IS NOT NULL
      AND root.oor_spent_txid <> root.onchain_spent_txid
      -- Matches vtxo_conflict_seed_ix predicate; also correct since
      -- offboard-connector rows are never OOR-spent.
      AND root.spend_state <> 'offboard-connector'
    UNION
    -- LATERAL + OFFSET 0 forces a nested loop over vtxo_txid_ix.
    -- Plain JOIN (or plain LATERAL, which the planner flattens)
    -- gets a hash join because Postgres's fixed 10x WorkTable size
    -- estimate for recursive CTEs makes per-row index lookups look
    -- expensive. OFFSET 0 is a semantic no-op that blocks subquery
    -- flattening.
    SELECT child.oor_spent_txid
    FROM conflicted c
    CROSS JOIN LATERAL (
        SELECT vtxo.oor_spent_txid
        FROM vtxo
        WHERE vtxo.vtxo_txid = c.txid
          AND vtxo.oor_spent_txid IS NOT NULL
        OFFSET 0
    ) AS child
)
SELECT txid FROM conflicted;

-- Vtxos that live on a conflicted OOR-spend tx (typically an arkoor):
-- descendants killed by a swept / exited ancestor.
CREATE VIEW v_conflicted_vtxos AS
SELECT v.id, v.vtxo_id, v.amount, v.expiry, v.spend_state,
       v.vtxo_txid, v.oor_spent_txid, v.created_at, v.updated_at
FROM vtxo v
JOIN v_conflicted_txids ct ON v.vtxo_txid = ct.txid
WHERE v.onchain_spent_txid IS NULL
  AND v.spend_state <> 'offboard-connector';

-- Frontier: vtxos we track on-chain that are still alive.
--
-- The conflicted flag marks rows that live on a dead OOR subtree:
-- their vtxo_txid is a conflicted OOR-spend tx (parent got swept /
-- exited, so this row will never confirm and holds no real money).
-- Summary views WHERE NOT conflicted for the "live money" number;
-- alerting queries filter WHERE conflicted (spendable / unregistered
-- / unclaimed / htlc-recv-unclaimed rows are the anomalous subset).
CREATE VIEW v_frontier_vtxos AS
SELECT v.id, v.vtxo_id, v.amount, v.expiry, v.spend_state,
       v.vtxo_txid, v.oor_spent_txid, v.frontier_at, v.confirmed_height,
       v.created_at, v.updated_at,
       EXISTS (
           SELECT 1 FROM v_conflicted_txids ct WHERE ct.txid = v.vtxo_txid
       ) AS conflicted
FROM vtxo v
WHERE v.frontier_at IS NOT NULL
  AND v.onchain_spent_txid IS NULL
  AND v.spend_state <> 'offboard-connector';


-- ---------------------------------------------------------------------
-- Gauge-mirror views (scalar totals). One-row views. Barking-bot reads
-- these to publish second_replica_vtxo_* gauges; the same rows are
-- available to Grafana ad-hoc panels for reconciliation.
-- ---------------------------------------------------------------------

CREATE VIEW v_vtxo_frontier_totals AS
SELECT COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_frontier_vtxos
WHERE NOT conflicted;

-- Conflicted frontier scalar totals. Barking-bot polls this to
-- publish a second_replica_vtxo_conflicted_* gauge and page on
-- growth. Any non-zero here means at least one frontier row lives
-- on a dead OOR subtree; whether that's alertable depends on the
-- ownership breakdown below (theirs/pending are user-facing).
CREATE VIEW v_vtxo_conflicted_frontier_totals AS
SELECT COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_frontier_vtxos
WHERE conflicted;

-- Conflicted frontier by ownership. Same theirs/pending/ours
-- mapping as v_frontier_ownership_totals: theirs and pending are
-- the anomalous subset (client thinks they own money that can't
-- confirm), ours is operational noise (arkoors that lost to a
-- sweep). Alert on theirs/pending count or volume; ours is
-- informational.
CREATE VIEW v_vtxo_conflicted_frontier_by_ownership AS
SELECT CASE spend_state::text
         WHEN 'spendable'           THEN 'theirs'
         WHEN 'unregistered'        THEN 'theirs'
         WHEN 'unclaimed'           THEN 'theirs'
         WHEN 'htlc-recv-unclaimed' THEN 'pending'
         WHEN 'spent'               THEN 'ours'
         WHEN 'pool'                THEN 'ours'
         WHEN 'round-forfeit'       THEN 'ours'
         WHEN 'offboard-forfeit'    THEN 'ours'
         WHEN 'ln-spent'            THEN 'ours'
         ELSE 'unknown'
       END AS ownership,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_frontier_vtxos
WHERE conflicted
GROUP BY 1;

-- Four-way split of on-chain spends of frontier vtxos:
--   offboard              : a legitimate offboard tx confirmed
--                           (offboarded_in matches the on-chain spend).
--   sweep_or_exit_no_oor  : no oor_spent_txid was ever recorded, then
--                           the outpoint was spent on-chain by either
--                           a server sweep or a user unilateral exit.
--   sweep_or_exit_after_oor : an OOR spend was recorded (arkoor,
--                             round-forfeit, or offboard-forfeit) but
--                             a different tx spent the outpoint
--                             on-chain, so the OOR is dead.
--   forfeit_broadcast     : oor_spent_txid = onchain_spent_txid, i.e.
--                           the recorded forfeit tx itself confirmed
--                           on-chain (server seizure). Silent in
--                           normal operation; watch for spikes.
CREATE VIEW v_vtxo_by_onchain_spent_kind AS
SELECT CASE
         WHEN v.offboarded_in = v.onchain_spent_txid THEN 'offboard'
         WHEN v.oor_spent_txid IS NULL THEN 'sweep_or_exit_no_oor'
         WHEN v.oor_spent_txid = v.onchain_spent_txid THEN 'forfeit_broadcast'
         ELSE 'sweep_or_exit_after_oor'
       END AS kind,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(v.amount), 0)::bigint AS volume
FROM vtxo v
WHERE v.onchain_spent_height IS NOT NULL
  AND v.spend_state <> 'offboard-connector'
GROUP BY kind;

CREATE VIEW v_vtxo_by_spend_state AS
SELECT v.spend_state::text AS spend_state,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(v.amount), 0)::bigint AS volume
FROM vtxo v
WHERE v.spend_state <> 'offboard-connector'
GROUP BY v.spend_state;


-- ---------------------------------------------------------------------
-- Frontier ownership & reconciliation.
--
-- Walks the OOR chain forward from every frontier vtxo to its current
-- leaves. A leaf is either (a) a vtxo that hasn't been OOR-spent
-- (oor_spent_txid IS NULL), or (b) a vtxo whose OOR-spend targets a
-- conflicted forfeit tx (see v_conflicted_txids) — the OOR-spend can
-- never confirm, so this row is effectively terminal. spend_state on
-- the leaf tells us who owns the money right now:
--   theirs  — client-controlled (spendable, unregistered, unclaimed)
--   pending — awaiting client action (htlc-recv-unclaimed)
--   ours    — server-owned but still parked as a vtxo (spent, pool,
--             round-forfeit, offboard-forfeit, ln-spent)
--
-- v_frontier_reconciliation surfaces frontier_volume vs the summed
-- ownership leaves. leaves_volume <= frontier_volume in normal
-- operation because each OOR split loses fees along the way. Expect a
-- small positive diff; alert on absolute size or sudden change, not on
-- diff != 0.
-- ---------------------------------------------------------------------

CREATE VIEW v_frontier_ownership_totals AS
WITH RECURSIVE descendants(vtxo_id, vtxo_txid, oor_spent_txid, spend_state, amount) AS (
    SELECT f.vtxo_id, f.vtxo_txid, f.oor_spent_txid, f.spend_state, f.amount
    FROM v_frontier_vtxos f
    WHERE NOT f.conflicted
    UNION
    -- LATERAL + OFFSET 0 to force nested-loop with an index scan;
    -- see v_conflicted_txids for the rationale. Same
    -- conflicted-forfeit exclusion as v_frontier_vtxos: the seed set
    -- is already clean, but the descent can otherwise cross into a
    -- dead subtree (e.g. F is a live frontier vtxo whose OOR-spend
    -- tx is conflicted; its child c would join here without this
    -- guard).
    SELECT c.vtxo_id, c.vtxo_txid, c.oor_spent_txid, c.spend_state, c.amount
    FROM descendants p
    CROSS JOIN LATERAL (
        SELECT vtxo.vtxo_id, vtxo.vtxo_txid, vtxo.oor_spent_txid,
               vtxo.spend_state, vtxo.amount, vtxo.onchain_spent_txid
        FROM vtxo
        WHERE vtxo.vtxo_txid = p.oor_spent_txid
        OFFSET 0
    ) AS c
    WHERE p.oor_spent_txid IS NOT NULL
      AND c.onchain_spent_txid IS NULL
      AND c.spend_state <> 'offboard-connector'
      AND NOT EXISTS (
          SELECT 1 FROM v_conflicted_txids ct WHERE ct.txid = c.vtxo_txid
      )
)
SELECT CASE spend_state::text
         WHEN 'spendable'           THEN 'theirs'
         WHEN 'unregistered'        THEN 'theirs'
         WHEN 'unclaimed'           THEN 'theirs'
         WHEN 'htlc-recv-unclaimed' THEN 'pending'
         WHEN 'spent'               THEN 'ours'
         WHEN 'pool'                THEN 'ours'
         WHEN 'round-forfeit'       THEN 'ours'
         WHEN 'offboard-forfeit'    THEN 'ours'
         WHEN 'ln-spent'            THEN 'ours'
         ELSE 'unknown' -- new/unmapped spend_state; surface it instead of dropping to NULL
       END AS ownership,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM descendants
-- Leaf if either (a) never OOR-spent, or (b) the OOR-spend targets a
-- conflicted forfeit tx. Case (b) — the "conflict-terminal leaf" —
-- keeps this row's amount inside leaves_volume so reconciliation stays
-- near zero on conflict events. Attribution goes by spend_state, which
-- will typically be 'spent' -> 'ours' for a conflicted OOR spend; the
-- money has really moved to whichever on-chain tx swept the parent,
-- but that lineage isn't recoverable from spend_state alone.
WHERE oor_spent_txid IS NULL
   OR EXISTS (SELECT 1 FROM v_conflicted_txids ct WHERE ct.txid = oor_spent_txid)
GROUP BY 1;

CREATE VIEW v_frontier_reconciliation AS
SELECT ft.n      AS frontier_n,
       ft.volume AS frontier_volume,
       COALESCE(ot.n, 0)      AS leaves_n,
       COALESCE(ot.volume, 0) AS leaves_volume,
       ft.volume - COALESCE(ot.volume, 0) AS diff_volume
FROM v_vtxo_frontier_totals ft
CROSS JOIN (
    SELECT SUM(n)::bigint AS n, SUM(volume)::bigint AS volume
    FROM v_frontier_ownership_totals
) ot;


-- ---------------------------------------------------------------------
-- Extended axis: bucketed by expiry (block height). Cardinality is
-- too high for Prometheus labels but fine for the replica.
-- ---------------------------------------------------------------------

CREATE VIEW v_vtxo_frontier_by_expiry AS
SELECT expiry,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_frontier_vtxos
WHERE NOT conflicted
GROUP BY expiry
ORDER BY expiry;

CREATE VIEW v_vtxo_conflicted_by_expiry AS
SELECT expiry,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_conflicted_vtxos
GROUP BY expiry
ORDER BY expiry;

CREATE VIEW v_vtxo_onchain_spent_by_kind_by_expiry AS
SELECT v.expiry,
       CASE
         WHEN v.offboarded_in = v.onchain_spent_txid THEN 'offboard'
         WHEN v.oor_spent_txid IS NULL THEN 'sweep_or_exit_no_oor'
         WHEN v.oor_spent_txid = v.onchain_spent_txid THEN 'forfeit_broadcast'
         ELSE 'sweep_or_exit_after_oor'
       END AS kind,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(v.amount), 0)::bigint AS volume
FROM vtxo v
WHERE v.onchain_spent_height IS NOT NULL
  AND v.spend_state <> 'offboard-connector'
GROUP BY v.expiry, kind
ORDER BY v.expiry, kind;

CREATE VIEW v_vtxo_frontier_by_state_by_expiry AS
SELECT expiry, spend_state::text AS spend_state,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(amount), 0)::bigint AS volume
FROM v_frontier_vtxos
WHERE NOT conflicted
GROUP BY expiry, spend_state
ORDER BY expiry, spend_state;


-- ---------------------------------------------------------------------
-- Extended axis: bucketed by block height of the on-chain spend.
-- Velocity of on-chain spends per block, kind-split.
-- ---------------------------------------------------------------------

CREATE VIEW v_vtxo_onchain_spent_by_height AS
SELECT v.onchain_spent_height,
       CASE
         WHEN v.offboarded_in = v.onchain_spent_txid THEN 'offboard'
         WHEN v.oor_spent_txid IS NULL THEN 'sweep_or_exit_no_oor'
         WHEN v.oor_spent_txid = v.onchain_spent_txid THEN 'forfeit_broadcast'
         ELSE 'sweep_or_exit_after_oor'
       END AS kind,
       COUNT(*)::bigint AS n,
       COALESCE(SUM(v.amount), 0)::bigint AS volume
FROM vtxo v
WHERE v.onchain_spent_height IS NOT NULL
  AND v.spend_state <> 'offboard-connector'
GROUP BY v.onchain_spent_height, kind
ORDER BY v.onchain_spent_height;


-- ---------------------------------------------------------------------
-- Late sweeps. Frontier vtxos whose expiry has passed by at least
-- `margin` blocks and that we haven't swept yet. barking-bot reads the
-- chain tip from captaind's telemetry (second_block_gauge, scraped via
-- alloy into Prometheus) and calls with a margin that matches the
-- alerting threshold (24 by default).
-- ---------------------------------------------------------------------

CREATE FUNCTION vtxo_late_sweeps(chain_tip integer, margin integer DEFAULT 24)
RETURNS TABLE(n bigint, volume bigint) LANGUAGE sql STABLE AS $$
    SELECT COUNT(*)::bigint,
           COALESCE(SUM(amount), 0)::bigint
    FROM v_frontier_vtxos
    WHERE NOT conflicted
      AND expiry + margin <= chain_tip;
$$;


-- ---------------------------------------------------------------------
-- Investigation: stuck funding txs. Funding txs (round, board,
-- vtxopool issuance) with no confirmation on their vtxo outputs.
-- Boards land already-confirmed (register_board requires it), so a
-- stuck row is almost always a round or a vtxopool issuance whose
-- funding tx never confirmed. Connector outputs are excluded from the
-- counts / totals so a round with only its connectors landed still
-- shows as stuck.
-- ---------------------------------------------------------------------

CREATE VIEW v_unconfirmed_funding_txs AS
SELECT vt.txid AS funding_txid,
       CASE
         WHEN r.funding_txid IS NOT NULL THEN 'round'
         ELSE 'other'
       END AS funding_kind,
       STRING_AGG(DISTINCT v.policy_type, ',' ORDER BY v.policy_type) AS policy_types,
       COUNT(v.vtxo_id)::bigint AS output_vtxos,
       COALESCE(SUM(v.amount), 0)::bigint AS total_amount,
       MIN(v.frontier_at) AS first_frontier_at,
       vt.signed_tx IS NOT NULL AS has_signed_bytes,
       vt.created_at AS vt_created_at
FROM virtual_transaction vt
JOIN vtxo v ON v.vtxo_txid = vt.txid
LEFT JOIN round r ON r.funding_txid = vt.txid
WHERE vt.is_funding
  AND v.confirmed_height IS NULL
  AND v.spend_state <> 'offboard-connector'
GROUP BY vt.txid, funding_kind, vt.signed_tx, vt.created_at
ORDER BY first_frontier_at;


-- ---------------------------------------------------------------------
-- Investigation: funding txs whose non-connector outputs never made it
-- to the frontier. Stronger anomaly than "unconfirmed" — the outputs
-- weren't even added to the watched set. Should be empty in normal
-- operation.
--
-- The 5-minute grace filter on vt.created_at is there because vtxopool
-- issuance (server/src/vtxopool.rs) inserts the vtxo tree and calls
-- add_funding_vtxos_to_frontier in two separate DB transactions with a
-- wallet persist in between; freshly issued rows are legitimately
-- un-frontiered for that window. finish_round and register_board are
-- atomic and don't need the grace, but the filter is cheap enough to
-- apply uniformly.
-- ---------------------------------------------------------------------

CREATE VIEW v_funding_no_frontier_outputs AS
SELECT vt.txid AS funding_txid,
       CASE
         WHEN r.funding_txid IS NOT NULL THEN 'round'
         ELSE 'other'
       END AS funding_kind,
       STRING_AGG(DISTINCT v.policy_type, ',' ORDER BY v.policy_type) AS policy_types,
       COUNT(v.vtxo_id)::bigint AS output_vtxos,
       COALESCE(SUM(v.amount), 0)::bigint AS total_amount,
       vt.signed_tx IS NOT NULL AS has_signed_bytes,
       vt.created_at AS vt_created_at
FROM virtual_transaction vt
JOIN vtxo v ON v.vtxo_txid = vt.txid
LEFT JOIN round r ON r.funding_txid = vt.txid
WHERE vt.is_funding
  AND v.spend_state <> 'offboard-connector'
  AND vt.created_at < NOW() - INTERVAL '5 minutes'
GROUP BY vt.txid, funding_kind, vt.signed_tx, vt.created_at
HAVING SUM(CASE WHEN v.frontier_at IS NOT NULL THEN 1 ELSE 0 END) = 0
ORDER BY vt.created_at;


-- ---------------------------------------------------------------------
-- Investigation: top cascade roots. For each sweep_or_exit_after_oor
-- on-chain spend, how much lineage did it kill?
--
-- Roots are aggregated by onchain_spent_txid because a single sweep
-- tx often consumes multiple input vtxos; each contributes one root
-- row but they share one cascade.
-- ---------------------------------------------------------------------

CREATE VIEW v_cascade_roots AS
WITH RECURSIVE conflicted_chain(txid, root_txid, depth) AS (
    SELECT DISTINCT root.oor_spent_txid, root.onchain_spent_txid, 1
    FROM vtxo root
    WHERE root.onchain_spent_txid IS NOT NULL
      AND root.oor_spent_txid IS NOT NULL
      AND root.oor_spent_txid <> root.onchain_spent_txid
      AND root.spend_state <> 'offboard-connector'
    UNION ALL
    -- LATERAL + OFFSET 0 to force nested-loop; see v_conflicted_txids.
    SELECT child.oor_spent_txid, cc.root_txid, cc.depth + 1
    FROM conflicted_chain cc
    CROSS JOIN LATERAL (
        SELECT vtxo.oor_spent_txid, vtxo.spend_state
        FROM vtxo
        WHERE vtxo.vtxo_txid = cc.txid
          AND vtxo.oor_spent_txid IS NOT NULL
        OFFSET 0
    ) AS child
    WHERE child.spend_state <> 'offboard-connector'
      AND cc.depth < 1000
),
-- Diamond-shape guard: a multi-input forfeit tx can be reached from
-- the same root via paths of different lengths (e.g. one input hits
-- it directly, another arrives via an extra OOR hop). UNION ALL keeps
-- both rows, which would double-count that tx's children in
-- descendants. Collapse to one row per (root, txid) and keep the
-- shortest lineage depth for the outer max_depth aggregation.
unique_conflicted_chain AS (
    SELECT root_txid, txid, MIN(depth)::integer AS depth
    FROM conflicted_chain
    GROUP BY root_txid, txid
),
descendants AS (
    SELECT uc.root_txid,
           COUNT(*)::bigint AS conflicted_count,
           COALESCE(SUM(v.amount), 0)::bigint AS conflicted_volume,
           MAX(uc.depth)::integer AS max_depth
    FROM unique_conflicted_chain uc
    JOIN vtxo v ON v.vtxo_txid = uc.txid
              AND v.onchain_spent_txid IS NULL
              AND v.spend_state <> 'offboard-connector'
    GROUP BY uc.root_txid
),
roots AS (
    SELECT root.onchain_spent_txid AS txid,
           MIN(root.onchain_spent_height) AS onchain_spent_height,
           COUNT(*)::bigint AS root_input_count,
           COALESCE(SUM(root.amount), 0)::bigint AS root_amount
    FROM vtxo root
    WHERE root.onchain_spent_txid IS NOT NULL
      AND root.oor_spent_txid IS NOT NULL
      AND root.oor_spent_txid <> root.onchain_spent_txid
      AND root.spend_state <> 'offboard-connector'
    GROUP BY root.onchain_spent_txid
)
SELECT r.txid AS onchain_spent_txid,
       r.onchain_spent_height,
       r.root_input_count,
       r.root_amount,
       d.conflicted_count,
       d.conflicted_volume,
       d.max_depth
FROM roots r
JOIN descendants d ON d.root_txid = r.txid
ORDER BY d.conflicted_volume DESC;
