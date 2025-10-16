
--
-- create a table for to represent boards
--

CREATE TABLE board (
	id             BIGSERIAL PRIMARY KEY,
	vtxo_id        TEXT REFERENCES vtxo(vtxo_id),
	expiry_height  INTEGER NOT NULL,
	swept_at       TIMESTAMPTZ,
	exited_at      TIMESTAMPTZ,
	created_at     TIMESTAMPTZ NOT NULL,
	updated_at     TIMESTAMPTZ NOT NULL,
	CONSTRAINT board_sweep_vtxo_unique UNIQUE (vtxo_id)
);

CREATE INDEX board_sweep_swept_at_ix ON board ((swept_at IS NULL));
CREATE INDEX board_sweep_exited_at_ix ON board ((exited_at IS NULL));
CREATE INDEX board_sweep_vtxo_id_ix ON board (vtxo_id);

ALTER TABLE vtxo DROP COLUMN board_swept_at;
-- Update the vtxo_history table to remove the board_swept_at column
ALTER TABLE vtxo_history DROP COLUMN board_swept_at;

-- Update the trigger function to remove board_swept_at
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

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
