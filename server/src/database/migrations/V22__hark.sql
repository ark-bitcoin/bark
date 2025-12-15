--
-- hArk stuff
--

-- round participation
CREATE TABLE round_participation (
	id                BIGSERIAL PRIMARY KEY,
	unlock_hash       TEXT,
	unlock_preimage   BYTEA,
	round_id          TEXT,
	created_at        TIMESTAMP NOT NULL
);

-- to query by unlock hash
CREATE UNIQUE INDEX round_participation_unlock_hash_uix ON round_participation (unlock_hash);

-- to filter pending participations
CREATE INDEX round_participation_round_id_null_ix ON round_participation ((round_id IS NULL));

CREATE TABLE round_part_input (
	participation_id        BIGINT NOT NULL REFERENCES round_participation(id),
	vtxo_id                 TEXT NOT NULL REFERENCES vtxo(vtxo_id),
	signed_forfeit_tx       BYTEA,
	signed_forfeit_claim_tx BYTEA
);

CREATE INDEX round_part_input_participation_id_ix ON round_part_input (participation_id);

CREATE TABLE round_part_output (
	participation_id BIGINT NOT NULL REFERENCES round_participation(id),
	policy           BYTEA NOT NULL,
	amount           BIGINT NOT NULL
);

CREATE INDEX round_part_output_participation_id_ix ON round_part_output (participation_id);


-- Remove forfeit_state column from vtxo table
ALTER TABLE vtxo DROP COLUMN forfeit_state;

-- Rename forfeit_round_id column to spent_in_round
ALTER TABLE vtxo RENAME COLUMN forfeit_round_id TO spent_in_round;

-- Update vtxo_history table to match vtxo table changes
ALTER TABLE vtxo_history DROP COLUMN forfeit_state;
ALTER TABLE vtxo_history RENAME COLUMN forfeit_round_id TO spent_in_round;

-- Drop indexes that reference the removed forfeit_state column
DROP INDEX IF EXISTS vtxo_has_forfeit_state_ix;
DROP INDEX IF EXISTS vtxo_spendable_ix;

-- Recreate the spendable index without forfeit_state reference
CREATE INDEX vtxo_spendable_ix ON vtxo ((oor_spent_txid IS NULL), (spent_in_round IS NULL), vtxo_id);

-- Drop unused columns from round table
ALTER TABLE round DROP COLUMN nb_input_vtxos;
ALTER TABLE round DROP COLUMN connector_key;

CREATE OR REPLACE FUNCTION vtxo_update_trigger()
	RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.spent_in_round,
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

