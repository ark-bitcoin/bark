-- Why a lightning send failed, stored as the kind's string form so the row
-- stays readable. NULL on success and on rows written before this migration,
-- which report an unspecified reason to the client.
--
-- Stored rather than joined back to lightning_payment_attempt: a mailbox entry
-- is a self-contained deliverable, and the attempt it came from can be
-- superseded by a later one for the same payment hash.

ALTER TABLE mailbox ADD COLUMN failure_reason TEXT;
