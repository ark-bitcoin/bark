-- `user_fee_sat` is written at initiation. NULL for pre-V57 rows. Routing
-- fee is derived from `final_amount_msat - amount_msat` at read time.

ALTER TABLE lightning_payment_attempt
	ADD COLUMN block_height INTEGER,
	ADD COLUMN user_fee_sat BIGINT;

ALTER TABLE lightning_payment_attempt_history
	ADD COLUMN block_height INTEGER,
	ADD COLUMN user_fee_sat BIGINT;

-- Same shape on the offboard side: `user_fee_sat` is written by
-- `register_offboard` and read on the `wallet_commit` FALSE->TRUE
-- transition to record fee telemetry exactly once. NULL for pre-V57 rows.
ALTER TABLE offboards ADD COLUMN user_fee_sat BIGINT;

CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error,
		block_height, user_fee_sat,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error,
		OLD.block_height, OLD.user_fee_sat,
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
