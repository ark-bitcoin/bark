-- Creates a table that holds all bitcoin transactions
-- that are known by the Ark Server.
--
-- This table can be pruned. Once a round is fully swept
-- we don't need the content anymore.

CREATE TABLE bitcoin_transaction (
    id bigint PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    txid TEXT UNIQUE NOT NULL,
    tx bytea NOT NULL,
    created_at timestamp with time zone NOT NULL
)
