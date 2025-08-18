-- Creates a table that holds tweaks used by the Ark server
-- to generate ephemeral cosign keys.
--
-- Once the lifetime of the key passes, it can be cleaned up.

CREATE TABLE ephemeral_tweak (
    id BIGSERIAL PRIMARY KEY,
    pubkey TEXT UNIQUE NOT NULL,
	tweak BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
	expires_at TIMESTAMP WITH TIME ZONE NOT NULL
)
