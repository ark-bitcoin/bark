
-- Add a dedicated column for round-participation-completed unlock hashes,
-- previously stored (incorrectly) in the shared payment_hash column.
ALTER TABLE mailbox ADD COLUMN unlock_hash TEXT;
