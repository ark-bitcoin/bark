-- The mode of the server, in one row. The server sets expiry_payouts
-- when it creates the database, before it co-signs any VTXO, and never
-- changes it. A flag is enough: the mode has no other state.
CREATE TABLE server_mode (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	expiry_payouts BOOLEAN NOT NULL
);
INSERT INTO server_mode (id, expiry_payouts) VALUES (1, FALSE);
