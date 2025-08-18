
--
-- create a table for the vtxopool
--

CREATE TABLE vtxo_pool (
	id             BIGSERIAL PRIMARY KEY,
	vtxo_id        TEXT REFERENCES vtxo(vtxo_id),
	expiry_height  INTEGER NOT NULL,
	amount         BIGINT NOT NULL,
	depth          SMALLINT NOT NULL,

	created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	spent_at       TIMESTAMPTZ,

	CONSTRAINT vtxo_pool_vtxo_unique
		UNIQUE (vtxo_id)
);

CREATE INDEX vtxo_pool_spent_ix ON vtxo_pool ((spent_at IS NULL));
CREATE INDEX vtxo_pool_vtxo_id_ix ON vtxo_pool (vtxo_id);
