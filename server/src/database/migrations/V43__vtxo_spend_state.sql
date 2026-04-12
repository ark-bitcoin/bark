-- Add spend_state column to vtxo table.
--
-- This column consolidates the three independent spend-tracking columns
-- (oor_spent_txid, spent_in_round, offboarded_in) into a single column
-- for double-spend protection.
--
-- Values: 'spendable', 'unclaimed', 'spent'

CREATE TYPE spend_state AS ENUM ('spendable', 'unclaimed', 'spent');

-- Add the column as nullable first
ALTER TABLE vtxo ADD COLUMN spend_state spend_state;

-- Backfill based on existing spend columns
UPDATE vtxo SET spend_state = CASE
	WHEN oor_spent_txid IS NULL AND spent_in_round IS NULL AND offboarded_in IS NULL
		THEN 'spendable'
	ELSE 'spent'
END::spend_state;

-- Make it non-nullable now that every row has a value
ALTER TABLE vtxo ALTER COLUMN spend_state SET NOT NULL;

-- Add the column to vtxo_history
ALTER TABLE vtxo_history ADD COLUMN spend_state spend_state;

-- Recreate the trigger to include spend_state
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
		server_pubkey, amount, anchor_point,
		oor_spent_txid, spent_in_round, offboarded_in,
		lightning_htlc_subscription_id, banned_until_height,
		spend_state,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.exit_delta, OLD.policy_type, OLD.policy,
		OLD.server_pubkey, OLD.amount, OLD.anchor_point,
		OLD.oor_spent_txid, OLD.spent_in_round, OLD.offboarded_in,
		OLD.lightning_htlc_subscription_id, OLD.banned_until_height,
		OLD.spend_state,
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
