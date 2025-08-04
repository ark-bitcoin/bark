

DROP VIEW IF EXISTS round;

ALTER TABLE all_round ADD COLUMN seq BIGINT;

WITH numbered AS (
    SELECT id, row_number() OVER (ORDER BY id) AS seq
    FROM all_round
)
UPDATE all_round AS a
SET seq = n.seq
FROM numbered AS n
WHERE a.id = n.id;

ALTER TABLE all_round ALTER COLUMN seq SET NOT NULL;


CREATE VIEW round AS
SELECT * FROM all_round WHERE deleted_at IS NULL;
