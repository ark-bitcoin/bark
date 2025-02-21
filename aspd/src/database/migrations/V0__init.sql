CREATE TABLE IF NOT EXISTS vtxo (
	id 				TEXT NOT NULL PRIMARY KEY,
	vtxo 			BYTEA NOT NULL,
	expiry 			INTEGER NOT NULL,
	oor_spent 		BYTEA,
	forfeit_sigs 	BYTEA[]
);

CREATE TABLE IF NOT EXISTS round (
	id 				TEXT NOT NULL PRIMARY KEY,
	tx 				BYTEA NOT NULL,
	signed_tree 	BYTEA NOT NULL,
	nb_input_vtxos 	INTEGER NOT NULL,
	expiry 			INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS arkoor_mailbox (
	id 				TEXT NOT NULL PRIMARY KEY,
	pubkey 			BYTEA NOT NULL,
	vtxo 			BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_sweep (
	txid 			TEXT NOT NULL PRIMARY KEY,
	tx 				BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS wallet (
	id 				SERIAL PRIMARY KEY,
	mnemonic 		TEXT NOT NULL,
	seed 			BYTEA
);

CREATE TABLE IF NOT EXISTS wallet_changeset (
	id 				SERIAL PRIMARY KEY,
	content			BYTEA
);