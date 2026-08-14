-- A payment attempt is a self-payment (intra-Ark) only when it was initiated
-- against an existing htlc subscription. That fact is decided at initiation
-- time, so record it on the attempt instead of deriving it from the presence
-- of a subscription with the same payment hash.
--
-- Deriving it meant a receive registered after an outgoing payment was
-- initiated would retroactively turn that payment into a "self-payment":
-- canceling the receive then failed the attempt, and the payer could revoke
-- its HTLCs while the actual lightning payment still settled.
ALTER TABLE lightning_payment_attempt
	ADD COLUMN lightning_htlc_subscription_id BIGINT
		REFERENCES lightning_htlc_subscription(id);

ALTER TABLE lightning_payment_attempt_history
	ADD COLUMN lightning_htlc_subscription_id BIGINT;

-- Record the new column in the history trigger.
CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, lightning_htlc_subscription_id, status, error,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.lightning_htlc_subscription_id, OLD.status, OLD.error,
		OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Backfill existing rows: an open attempt that has a subscription for the
-- same payment hash was (before this column existed) treated as a
-- self-payment, so preserve that interpretation for in-flight payments.
UPDATE lightning_payment_attempt lpa
	SET lightning_htlc_subscription_id = lhs.id
	FROM lightning_htlc_subscription lhs
	WHERE lhs.payment_hash = lpa.payment_hash
		AND lpa.status NOT IN ('failed', 'succeeded');
