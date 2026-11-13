-- The input VTXOs of the arkoor that settled a lightning receive on the
-- Ark address in the route hints of its invoice, sorted. A retry of that
-- arkoor is co-signed again, and any other arkoor is refused.
ALTER TABLE lightning_htlc_subscription ADD COLUMN arkoor_input_ids TEXT[];
