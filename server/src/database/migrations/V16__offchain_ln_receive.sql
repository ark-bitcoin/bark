
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


--
-- Create a table that links issued HTLC VTXOs with
-- payment subscriptions from the hold plugin
--

ALTER TABLE vtxo ADD COLUMN lightning_htlc_subscription_id BIGINT REFERENCES lightning_htlc_subscription (id);

CREATE INDEX vtxos_ln_htlc_sub_ix ON vtxo (lightning_htlc_subscription_id, vtxo_id);

ALTER TYPE lightning_htlc_subscription_status ADD VALUE 'htlcs-ready';
