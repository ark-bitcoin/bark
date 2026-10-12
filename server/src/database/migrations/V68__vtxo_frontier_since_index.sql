-- Serves the watchman's periodic frontier sync (`get_frontier_vtxos_since`),
-- which otherwise scans the whole vtxo table on every run.

CREATE INDEX IF NOT EXISTS vtxo_frontier_since_ix ON vtxo (frontier_at)
	WHERE frontier_at IS NOT NULL AND onchain_spent_height IS NULL;
