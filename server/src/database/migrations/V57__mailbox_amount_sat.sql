-- Amount of a lightning receive notification. Keeping it on the mailbox row
-- makes the message a stand-alone record, instead of one whose amount has to
-- be joined back onto the originating HTLC subscription on every read.

ALTER TABLE mailbox ADD COLUMN amount_sat BIGINT;

-- Backfill the notifications that were posted before the column existed. The
-- subscription keeps millisatoshi, which we round down like everywhere else.
UPDATE mailbox m
SET amount_sat = lhs.final_amount_msat / 1000
FROM lightning_htlc_subscription lhs
WHERE m.mailbox_type = 'ln-recv-pending'
	AND m.amount_sat IS NULL
	AND lhs.payment_hash = m.payment_hash
	AND lhs.receiver_mailbox_id = m.unblinded_mailbox_id
	AND lhs.final_amount_msat IS NOT NULL;
