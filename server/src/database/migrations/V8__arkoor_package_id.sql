ALTER TABLE all_arkoor_mailbox ADD COLUMN arkoor_package_id BYTEA NOT NULL;

DROP VIEW arkoor_mailbox;
CREATE VIEW arkoor_mailbox AS
SELECT * FROM all_arkoor_mailbox WHERE deleted_at IS NULL;