-- The outputs of an arkoor that settled a lightning receive and that pay
-- the Ark address in the route hints of its invoice, recorded when the
-- server co-signs it in expiry payout mode. mailbox_pk is the unblinded
-- mailbox of that address. Each VTXO pays at most one receive, so the VTXO
-- id is the key.
--
-- An output is delivered at delivered_height when the server holds its
-- signed transactions and the identical VTXO is posted to that mailbox,
-- while it is unspent, unexpired, not exited and has no expiry payout. It
-- stays delivered when its owner spends it later.
CREATE TABLE arkoor_receive_output (
	vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	subscription_id BIGINT NOT NULL REFERENCES lightning_htlc_subscription(id),
	mailbox_pk TEXT NOT NULL CHECK (length(mailbox_pk) = 66),
	delivered_height BIGINT
);
CREATE INDEX arkoor_receive_output_subscription_id_idx ON arkoor_receive_output (subscription_id);
