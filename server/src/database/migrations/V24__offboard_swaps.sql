

--
-- create offboards table
--

CREATE TABLE offboards (
	id            BIGSERIAL PRIMARY KEY,
	txid          TEXT NOT NULL,
	signed_tx     BYTEA NOT NULL,
	wallet_commit BOOLEAN NOT NULL,
	created_at    TIMESTAMP NOT NULL
);

CREATE INDEX offboards_txid_uix ON offboards (txid);
CREATE INDEX offboards_wallet_commit_false_ix ON offboards (id) WHERE wallet_commit IS FALSE;


--
-- add offboard spent to vtxo table
--

ALTER TABLE vtxo         ADD COLUMN offboarded_in TEXT;
ALTER TABLE vtxo_history ADD COLUMN offboarded_in TEXT;

-- recreate the spendable index 
DROP INDEX IF EXISTS vtxo_spendable_ix;
CREATE INDEX vtxo_spendable_ix ON vtxo (
	(oor_spent_txid IS NULL), (spent_in_round IS NULL), (offboarded_in IS NULL), vtxo_id
);

-- recreate history trigger
CREATE OR REPLACE FUNCTION vtxo_update_trigger()
	RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo, expiry, oor_spent_txid, spent_in_round,
		offboarded_in, created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.spent_in_round,
		OLD.offboarded_in, OLD.created_at, OLD.updated_at
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

