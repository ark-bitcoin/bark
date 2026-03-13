
CREATE TYPE mailbox_type AS ENUM ('arkoor-receive');
ALTER TABLE vtxo_mailbox ADD COLUMN mailbox_type mailbox_type NOT NULL DEFAULT 'arkoor-receive';
ALTER TABLE vtxo_mailbox ALTER COLUMN mailbox_type DROP DEFAULT;
