
--
-- add a column to record the lowest HTLC expiry of an accepted invoice
--


ALTER TABLE lightning_htlc_subscription ADD COLUMN lowest_incoming_htlc_expiry BIGINT;
