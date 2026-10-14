-- Seed recovery looks up vtxos by their encoded policy, ten thousand
-- policies per query, whatever their spend state.
CREATE INDEX vtxo_policy_ix ON vtxo (policy);
