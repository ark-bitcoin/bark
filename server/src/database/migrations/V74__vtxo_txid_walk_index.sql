-- The recursive walks down OOR chains look up vtxo by vtxo_txid and read
-- only these columns. Covering them lets the walks skip the wide vtxo rows,
-- which made a cold-cache walk take minutes.
CREATE INDEX vtxo_txid_walk_ix ON vtxo (vtxo_txid) INCLUDE (vtxo_id, oor_spent_txid, spend_state, amount, onchain_spent_txid);
DROP INDEX vtxo_txid_ix;
