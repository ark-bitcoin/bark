-- Virtual transactions are signed transactions that can be broadcast but haven't
-- hit the chain yet. Used by the watchman to bring vtxos onchain when needed.
--
-- txid: Transaction ID (primary key)
-- signed_tx: The fully signed transaction, or NULL if signatures aren't known yet.
--     This can happen after an arkoor exchange where the server signs first and
--     stores the unsigned vtx. Signatures are filled in once known - clients must
--     supply them before using their vtxo in a round, offboard, or lightning spend.
-- is_funding: True for funding transactions, false for other virtual transactions.
-- server_may_own_descendant_since: NULL if all descendants are owned by clients.
--     If a descendant is owned by the server, this is set to the timestamp when
--     that ownership began. The server MUST ensure that signed_tx is known for
--     all transactions where it owns a descendant.
CREATE TABLE IF NOT EXISTS virtual_transaction (
    txid TEXT PRIMARY KEY,
    signed_tx BYTEA,
    is_funding BOOLEAN NOT NULL,
    server_may_own_descendant_since TIMESTAMPTZ,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- Create a history table for virtual_transaction history
-- following the pattern of vtxo_history
CREATE TABLE IF NOT EXISTS virtual_transaction_history (
    txid TEXT,
    signed_tx BYTEA,
    is_funding BOOLEAN,
    server_may_own_descendant_since TIMESTAMPTZ,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Create a trigger for updating virtual transactions
CREATE OR REPLACE FUNCTION virtual_transaction_history_trigger()
	RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO virtual_transaction_history (
		txid, signed_tx, is_funding, server_may_own_descendant_since, created_at, updated_at
	) VALUES (
		OLD.txid, OLD.signed_tx, OLD.is_funding, OLD.server_may_own_descendant_since, OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at AND NEW.updated_at <> NOW() THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Create a trigger for updating virtual transactions
CREATE OR REPLACE TRIGGER virtual_transaction_history_update
    BEFORE UPDATE ON virtual_transaction
    FOR EACH ROW
    EXECUTE FUNCTION virtual_transaction_history_trigger();

-- Add vtxo_txid column to vtxo table
-- This column stores the txid of the vtxo for efficient lookups
ALTER TABLE vtxo ADD COLUMN vtxo_txid TEXT;

CREATE INDEX vtxo_txid_ix ON vtxo (vtxo_txid);

-- Also add to history table
ALTER TABLE vtxo_history ADD COLUMN vtxo_txid TEXT;

-- Update the vtxo history trigger to include the new columns
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
	RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, oor_spent_txid, spent_in_round,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.spent_in_round,
		OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at AND new.updated_AT <> NOW() THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

