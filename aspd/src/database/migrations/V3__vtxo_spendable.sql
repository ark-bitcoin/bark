

CREATE OR REPLACE VIEW vtxo AS
SELECT *, (oor_spent IS NULL AND forfeit_sigs IS NULL) AS spendable
FROM all_vtxo WHERE deleted_at IS NULL ;

