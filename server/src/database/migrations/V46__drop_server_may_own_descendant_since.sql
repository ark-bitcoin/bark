ALTER TABLE virtual_transaction DROP COLUMN server_may_own_descendant_since;
ALTER TABLE virtual_transaction_history DROP COLUMN server_may_own_descendant_since;

CREATE OR REPLACE FUNCTION virtual_transaction_history_trigger()
	RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO virtual_transaction_history (
		txid, signed_tx, is_funding, created_at, updated_at
	) VALUES (
		OLD.txid, OLD.signed_tx, OLD.is_funding, OLD.created_at, OLD.updated_at
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
