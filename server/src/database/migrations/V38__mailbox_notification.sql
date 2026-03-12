-- Add lightning receive notification type to mailbox_type enum
ALTER TYPE mailbox_type ADD VALUE 'ln-recv-pending';

-- Store client's mailbox ID on lightning invoices
ALTER TABLE lightning_invoice ADD COLUMN mailbox_id TEXT;
