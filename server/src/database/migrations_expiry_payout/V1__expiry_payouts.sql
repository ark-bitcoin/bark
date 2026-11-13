-- The mode of the server, in one row. The server sets expiry_payouts
-- when it creates the database, before it co-signs any VTXO, and never
-- changes it. A flag is enough: the mode has no other state.
CREATE TABLE server_mode (
	id INTEGER PRIMARY KEY CHECK (id = 1),
	expiry_payouts BOOLEAN NOT NULL
);
INSERT INTO server_mode (id, expiry_payouts) VALUES (1, FALSE);

-- The id of the signed intent of a lightning send. A request that is sent
-- again finds its attempt by this id and starts no other payment.
ALTER TABLE lightning_payment_attempt
	ADD COLUMN intent_id TEXT UNIQUE CHECK (intent_id IS NULL OR length(intent_id) = 64);

-- The owner of a board, bound when the server co-signs its exit.
ALTER TABLE board_exit
	ADD COLUMN owner_mailbox TEXT
	CHECK (owner_mailbox IS NULL OR length(owner_mailbox) = 66);
ALTER TABLE board_exit
	ADD COLUMN user_pubkey TEXT
	CHECK (user_pubkey IS NULL OR length(user_pubkey) = 66);
CREATE INDEX board_exit_exit_txid_idx ON board_exit(exit_txid);

-- A round participation that an expiry payout cancelled. The server can
-- delete a superseded participation, so this row has no foreign key and
-- keeps the unlock hash, which must never get its preimage.
CREATE TABLE expiry_cancelled_participation (
	participation_id BIGINT PRIMARY KEY,
	unlock_hash TEXT UNIQUE
);

-- The payout of one expired tree. The decision never changes. The spends
-- of its inputs on-chain give its state, see v_expiry_payout_state.
CREATE TABLE expiry_payout (
	id BIGSERIAL PRIMARY KEY,
	expiry_height INTEGER NOT NULL CHECK (expiry_height >= 0),
	broadcast_at TIMESTAMPTZ
);

-- The tables below hold rows of an expiry payout that nothing references,
-- so each one uses its natural key.

-- The tree root that a payout spends.
CREATE TABLE expiry_payout_input (
	expiry_payout_id BIGINT NOT NULL REFERENCES expiry_payout(id),
	vtxo_id TEXT NOT NULL REFERENCES vtxo(vtxo_id),
	PRIMARY KEY (expiry_payout_id, vtxo_id)
);

-- Each signed payout transaction. An earlier attempt can confirm after a
-- fee bump, so every attempt stays.
CREATE TABLE expiry_payout_attempt (
	expiry_payout_id BIGINT NOT NULL REFERENCES expiry_payout(id),
	txid TEXT NOT NULL CHECK (length(txid) = 64),
	signed_tx BYTEA NOT NULL,
	fee_sat BIGINT NOT NULL CHECK (fee_sat >= 0),
	PRIMARY KEY (expiry_payout_id, txid),
	UNIQUE (txid)
);

-- The decision for each VTXO of the tree: who gets its value, and how
-- much. A VTXO with a row is decided, and the spend guard refuses any
-- change to it.
CREATE TABLE expiry_payout_vtxo (
	expiry_payout_id BIGINT NOT NULL REFERENCES expiry_payout(id),
	vtxo_id TEXT NOT NULL REFERENCES vtxo(vtxo_id),
	owner_mailbox TEXT CHECK (owner_mailbox IS NULL OR length(owner_mailbox) = 66),
	disposition TEXT NOT NULL CHECK (disposition IN ('owner', 'operator')),
	gross_sat BIGINT NOT NULL CHECK (gross_sat > 0),
	fee_sat BIGINT NOT NULL CHECK (fee_sat >= 0),
	payout_sat BIGINT NOT NULL CHECK (payout_sat >= 0),
	-- A decision that rests on a lightning payment is made again after a
	-- conflict. Any other decision is repeated as it is.
	replannable BOOLEAN NOT NULL,
	PRIMARY KEY (expiry_payout_id, vtxo_id),
	CHECK ((disposition = 'owner' AND owner_mailbox IS NOT NULL
		AND gross_sat = fee_sat + payout_sat)
		OR (disposition = 'operator' AND fee_sat = 0 AND payout_sat = 0))
);
CREATE INDEX expiry_payout_vtxo_vtxo_id_idx ON expiry_payout_vtxo(vtxo_id);

-- The state of each expiry payout, from the spends of its inputs seen by
-- the watchman. It is confirmed when one of its attempts spends every
-- input. It is conflicted when another transaction spends an input, or
-- when another payout of one of its VTXOs confirmed. Else it is pending.
CREATE VIEW v_expiry_payout_state AS
WITH observed AS (
	SELECT a.id,
		COUNT(i.vtxo_id) > 0
			AND BOOL_AND(v.onchain_spent_txid IS NOT NULL AND b.height IS NOT NULL
				AND EXISTS (SELECT 1 FROM expiry_payout_attempt p
					WHERE p.expiry_payout_id = a.id AND p.txid = v.onchain_spent_txid))
			AND COUNT(DISTINCT v.onchain_spent_txid) = 1 AS confirmed,
		BOOL_OR(v.onchain_spent_txid IS NOT NULL AND NOT EXISTS (
			SELECT 1 FROM expiry_payout_attempt p
			WHERE p.expiry_payout_id = a.id AND p.txid = v.onchain_spent_txid))
			OR COUNT(DISTINCT v.onchain_spent_txid) > 1 AS conflicted,
		MIN(v.onchain_spent_txid) AS confirmed_txid,
		MIN(b.height) AS height
	FROM expiry_payout a
	LEFT JOIN expiry_payout_input i ON i.expiry_payout_id = a.id
	LEFT JOIN vtxo v ON v.vtxo_id = i.vtxo_id
	LEFT JOIN watchmand_block b ON b.height = v.onchain_spent_height
	GROUP BY a.id
)
SELECT a.id, a.expiry_height,
	CASE WHEN o.confirmed THEN o.confirmed_txid ELSE latest.txid END AS payout_txid,
	CASE WHEN o.confirmed THEN winner.signed_tx ELSE latest.signed_tx END AS payout_tx,
	a.broadcast_at,
	CASE WHEN o.confirmed THEN 'confirmed'
		WHEN o.conflicted OR EXISTS (
			SELECT 1 FROM expiry_payout_vtxo c
			JOIN expiry_payout_vtxo paid ON paid.vtxo_id = c.vtxo_id
			JOIN observed prior ON prior.id = paid.expiry_payout_id
			WHERE c.expiry_payout_id = a.id AND prior.confirmed AND prior.id <> a.id)
		THEN 'conflicted' ELSE 'pending' END AS status,
	CASE WHEN o.confirmed THEN o.height END AS confirmed_height
FROM expiry_payout a
JOIN observed o ON o.id = a.id
LEFT JOIN expiry_payout_attempt winner
	ON winner.expiry_payout_id = a.id AND winner.txid = o.confirmed_txid
-- Each replacement raises the absolute fee, so the attempt with the
-- highest fee is the latest.
LEFT JOIN LATERAL (SELECT p.txid, p.signed_tx FROM expiry_payout_attempt p
	WHERE p.expiry_payout_id = a.id ORDER BY p.fee_sat DESC LIMIT 1) latest ON TRUE;

-- The owner mailbox of each VTXO that an owner holds, recorded when the
-- VTXO is created. A side table keeps the vtxo table unchanged, and the
-- VTXO id is its key because each VTXO has at most one row.
CREATE TABLE vtxo_owner_mailbox (
	vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	mailbox_pk TEXT NOT NULL CHECK (length(mailbox_pk) = 66)
);
