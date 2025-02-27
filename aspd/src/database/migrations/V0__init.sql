CREATE TABLE IF NOT EXISTS all_vtxo (
	id 				TEXT NOT NULL PRIMARY KEY,
	vtxo 			BYTEA NOT NULL,
	expiry 			INTEGER NOT NULL,
	oor_spent 		BYTEA,
	forfeit_sigs 	BYTEA[],

	deleted_at 		TIMESTAMPTZ
);

CREATE VIEW vtxo AS
SELECT * FROM all_vtxo WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS all_round (
	id 				TEXT NOT NULL PRIMARY KEY,
	tx 				BYTEA NOT NULL,
	signed_tree 	BYTEA NOT NULL,
	nb_input_vtxos 	INTEGER NOT NULL,
	expiry 			INTEGER NOT NULL,

	deleted_at 		TIMESTAMPTZ
);

CREATE VIEW round AS
SELECT * FROM all_round WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS all_arkoor_mailbox (
	id 				TEXT NOT NULL PRIMARY KEY,
	pubkey 			BYTEA NOT NULL,
	vtxo 			BYTEA NOT NULL,

	deleted_at 		TIMESTAMPTZ
);

CREATE VIEW arkoor_mailbox AS
SELECT * FROM all_arkoor_mailbox WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS all_pending_sweep (
	txid 			TEXT NOT NULL PRIMARY KEY,
	tx 				BYTEA NOT NULL,

	deleted_at 		TIMESTAMPTZ
);

CREATE VIEW pending_sweep AS
SELECT * FROM all_pending_sweep WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS wallet_changeset (
	id 				SERIAL PRIMARY KEY,
	content			BYTEA
);