-- How long the lightning node was told to keep retrying the payment, as asked
-- by the client or the server default. Written at initiation so the xpay
-- monitor knows when the node has stopped retrying. NULL for pre-V66 rows,
-- for which the configured `cln_xpay_timeout` applies.

ALTER TABLE lightning_payment_attempt
	ADD COLUMN retry_for_secs INTEGER;

ALTER TABLE lightning_payment_attempt_history
	ADD COLUMN retry_for_secs INTEGER;

CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error,
		block_height, user_fee_sat, user_agent, retry_for_secs,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error,
		OLD.block_height, OLD.user_fee_sat, OLD.user_agent, OLD.retry_for_secs,
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
$$;
