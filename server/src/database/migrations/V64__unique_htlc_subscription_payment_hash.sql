--
-- A payment hash carries at most one receive subscription. This reflects the
-- current situation: bark never asks for a second invoice on the same hash,
-- and the server now refuses such a request.
--

DROP INDEX lightning_htlc_subscription_payment_hash_ix;
CREATE UNIQUE INDEX lightning_htlc_subscription_payment_hash_uix
	ON lightning_htlc_subscription (payment_hash);
