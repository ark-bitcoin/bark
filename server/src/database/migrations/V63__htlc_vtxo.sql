-- Direction is from the server's point of view: htlc-send is incoming,
-- htlc-receive is outgoing.
CREATE TYPE htlc_direction AS ENUM ('incoming', 'outgoing');

-- NULL while the htlc is unresolved.
CREATE TYPE htlc_resolution AS ENUM ('fulfilled', 'revoked');

-- HTLC data of vtxos with an htlc policy, one row per htlc vtxo.

CREATE TABLE htlc_vtxo (
	id BIGINT PRIMARY KEY REFERENCES vtxo(id),
	payment_hash TEXT NOT NULL,
	htlc_expiry INTEGER NOT NULL,
	direction htlc_direction NOT NULL,
	resolution htlc_resolution
);

CREATE INDEX htlc_vtxo_payment_hash_ix ON htlc_vtxo (payment_hash);
