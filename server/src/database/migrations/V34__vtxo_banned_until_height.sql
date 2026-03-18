ALTER TABLE vtxo ADD COLUMN banned_until_height INTEGER;

-- Add missing columns to vtxo_history
ALTER TABLE vtxo_history ADD COLUMN lightning_htlc_subscription_id BIGINT;
ALTER TABLE vtxo_history ADD COLUMN banned_until_height INTEGER;

-- Recreate the trigger function to include banned_until_height
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
		server_pubkey, amount, anchor_point,
		oor_spent_txid, spent_in_round, offboarded_in,
		lightning_htlc_subscription_id, banned_until_height,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.exit_delta, OLD.policy_type, OLD.policy,
		OLD.server_pubkey, OLD.amount, OLD.anchor_point,
		OLD.oor_spent_txid, OLD.spent_in_round, OLD.offboarded_in,
		OLD.lightning_htlc_subscription_id, OLD.banned_until_height,
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
