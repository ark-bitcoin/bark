--
-- add a column to store signed vtxos owned by the vtxo pool
--

ALTER TABLE vtxo_pool ADD COLUMN vtxo BYTEA NOT NULL;