
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
