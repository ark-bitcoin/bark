

DROP VIEW IF EXISTS vtxo;

ALTER TABLE all_vtxo
	DROP COLUMN forfeit_sigs,
	ADD COLUMN forfeit_state BYTEA;

CREATE VIEW vtxo AS
SELECT *, (oor_spent IS NULL AND forfeit_state IS NULL) AS spendable
FROM all_vtxo
WHERE deleted_at IS NULL;


CREATE TABLE forfeits_wallet_changeset (
	id       SERIAL PRIMARY KEY,
	content  BYTEA
);


CREATE TABLE forfeits_round_state (
	round_id            TEXT NOT NULL PRIMARY KEY,
	nb_connectors_used  INTEGER NOT NULL
);


CREATE TABLE forfeits_claim_state (
	vtxo_id          TEXT NOT NULL PRIMARY KEY,
	connector_tx     BYTEA,
	connector_cpfp   BYTEA,
	connector_point  BYTEA NOT NULL,
	forfeit_tx       BYTEA NOT NULL,
	forfeit_cpfp     BYTEA
);


