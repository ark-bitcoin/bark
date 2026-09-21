-- `max_routing_fee_msat` is the routing budget handed to CLN as xpay's
-- `maxfee`. Written at initiation, NULL for pre-V68 rows. Makes budget
-- utilisation exact instead of reconstructed from `user_fee_sat *
-- ln_max_fee_ppm`, which goes stale whenever that config is retuned.

ALTER TABLE lightning_payment_attempt
	ADD COLUMN max_routing_fee_msat BIGINT;

ALTER TABLE lightning_payment_attempt_history
	ADD COLUMN max_routing_fee_msat BIGINT;

-- Recreated for the new column. Also restores `lightning_htlc_subscription_id`,
-- which V61 dropped from the insert list, so history has held NULL since.
CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error,
		block_height, user_fee_sat, user_agent, retry_for_secs, max_routing_fee_msat,
		lightning_htlc_subscription_id,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error,
		OLD.block_height, OLD.user_fee_sat, OLD.user_agent, OLD.retry_for_secs, OLD.max_routing_fee_msat,
		OLD.lightning_htlc_subscription_id,
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
