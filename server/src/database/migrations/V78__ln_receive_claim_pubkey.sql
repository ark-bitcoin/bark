-- The key a receiver committed to when starting a lightning receive. When
-- set, only that key can prepare the claim of the receive.
ALTER TABLE lightning_htlc_subscription ADD COLUMN claim_pubkey TEXT;
