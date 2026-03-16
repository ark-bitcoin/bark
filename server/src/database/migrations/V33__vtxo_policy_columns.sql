--
-- Add exit_delta, policy_type, policy, server_pubkey, amount and
-- anchor_point columns to vtxo and vtxo_history. These columns are
-- nullable (existing rows have NULL), but once set they must never be
-- changed.
--

ALTER TABLE vtxo ADD COLUMN exit_delta INTEGER;
ALTER TABLE vtxo ADD COLUMN policy_type TEXT;
ALTER TABLE vtxo ADD COLUMN policy BYTEA;
ALTER TABLE vtxo ADD COLUMN server_pubkey TEXT;
ALTER TABLE vtxo ADD COLUMN amount BIGINT;
ALTER TABLE vtxo ADD COLUMN anchor_point TEXT;

ALTER TABLE vtxo_history ADD COLUMN exit_delta INTEGER;
ALTER TABLE vtxo_history ADD COLUMN policy_type TEXT;
ALTER TABLE vtxo_history ADD COLUMN policy BYTEA;
ALTER TABLE vtxo_history ADD COLUMN server_pubkey TEXT;
ALTER TABLE vtxo_history ADD COLUMN amount BIGINT;
ALTER TABLE vtxo_history ADD COLUMN anchor_point TEXT;

-- Recreate the trigger function to copy the new columns into vtxo_history.
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
		server_pubkey, amount, anchor_point,
		oor_spent_txid, spent_in_round,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.exit_delta, OLD.policy_type, OLD.policy,
		OLD.server_pubkey, OLD.amount, OLD.anchor_point,
		OLD.oor_spent_txid, OLD.spent_in_round,
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
