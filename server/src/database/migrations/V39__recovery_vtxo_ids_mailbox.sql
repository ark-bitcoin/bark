
ALTER TYPE mailbox_type ADD VALUE 'recovery-vtxo-id';

-- Change unique constraint from (vtxo_id) to (mailbox_type, vtxo_id)
-- This allows the same vtxo_id to appear in different mailbox types
DROP INDEX vtxo_mailbox_vtxo_id;
CREATE UNIQUE INDEX mailbox_mailbox_type_vtxo_id_uix ON mailbox (mailbox_type, vtxo_id);
