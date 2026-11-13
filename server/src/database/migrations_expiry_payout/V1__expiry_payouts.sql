-- The mode of the server, in one row. The server sets expiry_payouts
-- when it creates the database, before it co-signs any VTXO, and never
-- changes it. A flag is enough: the mode has no other state.
CREATE TABLE server_mode (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	expiry_payouts BOOLEAN NOT NULL
);
INSERT INTO server_mode (id, expiry_payouts) VALUES (1, FALSE);

-- The owner of a board, bound when the server co-signs its exit.
ALTER TABLE board_exit
	ADD COLUMN owner_mailbox TEXT
	CHECK (owner_mailbox IS NULL OR length(owner_mailbox) = 66);
ALTER TABLE board_exit
	ADD COLUMN user_pubkey TEXT
	CHECK (user_pubkey IS NULL OR length(user_pubkey) = 66);

-- The owner mailbox of each VTXO that an owner holds, recorded when the
-- VTXO is created. A side table keeps the vtxo table unchanged, and the
-- VTXO id is its key because each VTXO has at most one row.
CREATE TABLE vtxo_owner_mailbox (
	vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	mailbox_pk TEXT NOT NULL CHECK (length(mailbox_pk) = 66)
);
