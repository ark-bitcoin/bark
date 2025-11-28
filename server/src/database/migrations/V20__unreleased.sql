--
-- add a column to store signed vtxos owned by the vtxo pool
--

ALTER TABLE vtxo_pool ADD COLUMN vtxo BYTEA NOT NULL;
ALTER TABLE vtxo_pool DROP COLUMN depth;

CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO vtxo_history (
        id, vtxo_id, vtxo, expiry, oor_spent_txid, forfeit_state, forfeit_round_id,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.vtxo_id, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.forfeit_state, OLD.forfeit_round_id,
        OLD.created_at, OLD.updated_at
    );

    IF NEW.updated_at = OLD.updated_at AND new.updated_AT <> NOW() THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
