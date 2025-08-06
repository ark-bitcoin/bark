

DROP VIEW IF EXISTS vtxo;

ALTER TABLE all_vtxo ADD COLUMN forfeit_round_id TEXT;

CREATE VIEW vtxo AS
SELECT *, (oor_spent IS NULL AND forfeit_state IS NULL) AS spendable
FROM all_vtxo
WHERE deleted_at IS NULL;




