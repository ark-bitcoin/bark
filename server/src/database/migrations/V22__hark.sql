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

