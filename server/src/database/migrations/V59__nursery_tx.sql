-- Transactions handed to the TxNursery for broadcast. The nursery
-- rebroadcasts each tx until it confirms and warns the operator once
-- confirm_target_height passes; abandoning a tx sets abandoned_at
-- and makes the nursery give up on it.

CREATE TABLE nursery_tx (
	id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	txid TEXT UNIQUE NOT NULL,
	tx bytea NOT NULL,
	confirm_target_height INTEGER NOT NULL,
	confirmed_at_height INTEGER,
	abandoned_at timestamp with time zone,
	created_at timestamp with time zone NOT NULL,
	updated_at timestamp with time zone NOT NULL
);
