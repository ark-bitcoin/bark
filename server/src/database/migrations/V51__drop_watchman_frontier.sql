-- Drop watchman_vtxo_frontier and fold its columns into vtxo so captaind
-- and watchmand operate on a single row per vtxo. Locking sweep / exit /
-- continuation bookkeeping against the same table is easier to reason
-- about than coordinating two tables joined on vtxo_id.
--
-- Frontier membership is recorded by a frontier_at timestamp: NULL means
-- the vtxo is not in the frontier; NOT NULL records when it joined. This
-- preserves the previous semantic (a row existed in watchman_vtxo_frontier)
-- while keeping all sweep / exit / continuation state on a single table.

ALTER TABLE vtxo ADD COLUMN frontier_at TIMESTAMPTZ;
ALTER TABLE vtxo ADD COLUMN confirmed_height INTEGER;
ALTER TABLE vtxo ADD COLUMN onchain_spent_height INTEGER;
ALTER TABLE vtxo ADD COLUMN onchain_spent_txid TEXT;

-- Existing rows: frontier_at takes the vtxo's created_at as a best-effort
-- proxy (we don't have the original frontier-insert time, but funding
-- outputs were always added at vtxo creation in practice, and approximate
-- timestamps are only used for debug ordering, not correctness).
UPDATE vtxo
SET frontier_at = vtxo.created_at,
	confirmed_height = f.confirmed_height,
	onchain_spent_height = f.spent_height,
	onchain_spent_txid = f.spent_txid,
	updated_at = NOW()
FROM watchman_vtxo_frontier f
WHERE vtxo.vtxo_id = f.vtxo_id;

DROP TABLE watchman_vtxo_frontier;

-- Mirror the new columns on vtxo_history.
ALTER TABLE vtxo_history ADD COLUMN frontier_at TIMESTAMPTZ;
ALTER TABLE vtxo_history ADD COLUMN confirmed_height INTEGER;
ALTER TABLE vtxo_history ADD COLUMN onchain_spent_height INTEGER;
ALTER TABLE vtxo_history ADD COLUMN onchain_spent_txid TEXT;

-- Recreate the trigger to copy the new columns into vtxo_history.
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
		server_pubkey, amount, anchor_point,
		oor_spent_txid, spent_in_round, offboarded_in,
		lightning_htlc_subscription_id, banned_until_height,
		spend_state,
		frontier_at, confirmed_height, onchain_spent_height, onchain_spent_txid,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.exit_delta, OLD.policy_type, OLD.policy,
		OLD.server_pubkey, OLD.amount, OLD.anchor_point,
		OLD.oor_spent_txid, OLD.spent_in_round, OLD.offboarded_in,
		OLD.lightning_htlc_subscription_id, OLD.banned_until_height,
		OLD.spend_state,
		OLD.frontier_at, OLD.confirmed_height, OLD.onchain_spent_height, OLD.onchain_spent_txid,
		OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at AND new.updated_at <> NOW() THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;
