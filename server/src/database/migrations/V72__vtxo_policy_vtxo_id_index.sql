-- Seed recovery reads the vtxos of one policy in pages ordered by vtxo id,
-- so that a policy with many vtxos is never read in a single query. The new
-- index also serves the lookups by policy alone.
CREATE INDEX vtxo_policy_vtxo_id_ix ON vtxo (policy, vtxo_id);
DROP INDEX vtxo_policy_ix;
