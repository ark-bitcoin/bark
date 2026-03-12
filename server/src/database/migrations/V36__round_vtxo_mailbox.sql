
-- Add unblinded_mailbox_id column to round_part_output table for wallet recovery support
ALTER TABLE round_part_output ADD COLUMN unblinded_mailbox_id TEXT;

ALTER TYPE mailbox_type ADD VALUE 'round-participation-completed';

ALTER TABLE vtxo_mailbox RENAME TO mailbox;

ALTER TABLE mailbox ADD COLUMN payment_hash TEXT;
ALTER TABLE mailbox ALTER COLUMN vtxo_id DROP NOT NULL;
ALTER TABLE mailbox ALTER COLUMN vtxo DROP NOT NULL;

