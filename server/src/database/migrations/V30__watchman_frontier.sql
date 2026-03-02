CREATE TABLE IF NOT EXISTS watchman_vtxo_frontier (
	vtxo_id          TEXT NOT NULL PRIMARY KEY REFERENCES vtxo(vtxo_id),
	confirmed_height INTEGER,
	spent_height     INTEGER,
	spent_txid       TEXT
);
