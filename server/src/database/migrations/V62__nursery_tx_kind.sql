-- What each nursery tx is for; shown in the operator's report and later
-- used to pick per-kind fee bump behavior.
--
-- Rows created before this migration can't be classified, so they get
-- 'round', the kind whose follow-up will be the most urgent; at worst
-- that overpays a little for a tx of another kind.

CREATE TYPE nursery_tx_kind AS ENUM ('round', 'offboard', 'vtxopool', 'internal');

ALTER TABLE nursery_tx ADD COLUMN kind nursery_tx_kind NOT NULL DEFAULT 'round';
ALTER TABLE nursery_tx ALTER COLUMN kind DROP DEFAULT;
