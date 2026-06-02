-- Join table linking lightning payment attempts to the HTLC-send vtxos they
-- were initiated with. Populated by initiate_lightning_payment after the
-- attempt row is created. Used at settlement to find the vtxos to flip to
-- 'ln-spent' without scanning every server-htlc-send row.
CREATE TABLE lightning_payment_attempt_htlc_vtxo (
	lightning_payment_attempt_id BIGINT NOT NULL
		REFERENCES lightning_payment_attempt(id) ON DELETE CASCADE,
	vtxo_id TEXT NOT NULL REFERENCES vtxo(vtxo_id),
	PRIMARY KEY (lightning_payment_attempt_id, vtxo_id)
);

CREATE INDEX lightning_payment_attempt_htlc_vtxo_vtxo_id_ix
	ON lightning_payment_attempt_htlc_vtxo(vtxo_id);
