CREATE TABLE htlc_settlement (
	id BIGSERIAL PRIMARY KEY,
	payment_hash TEXT NOT NULL UNIQUE,
	preimage BYTEA NOT NULL,
	created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX htlc_settlement_payment_hash_ix ON htlc_settlement(payment_hash);
