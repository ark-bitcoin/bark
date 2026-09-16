-- `user_agent` is the raw `x-user-agent` the initiating client sent, verbatim
-- (validated as `<name>/<version>`, so it is well-formed). Not the bucketed
-- `rpc.client` metric label: that drops the version and collapses names past
-- the bucket budget to `other`, neither of which a text column needs.
-- Written once at initiation, on the RPC task that still has the task-local in
-- scope; every later status transition is emitted by the xpay monitor, which
-- has no client of its own and reads it back from here. NULL when the client
-- sent no header, and for rows created before this migration.

ALTER TABLE lightning_payment_attempt ADD COLUMN user_agent TEXT;

ALTER TABLE lightning_payment_attempt_history ADD COLUMN user_agent TEXT;

CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error,
		block_height, user_fee_sat, user_agent,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error,
		OLD.block_height, OLD.user_fee_sat, OLD.user_agent,
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

-- The same attribution for receives: the client that generated the invoice.
-- The settlement metric is emitted on the claiming RPC task normally, but by
-- the hold settler after a restart, which reads the client back from here.

ALTER TABLE lightning_htlc_subscription ADD COLUMN user_agent TEXT;

ALTER TABLE lightning_htlc_subscription_history ADD COLUMN user_agent TEXT;

CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	INSERT INTO lightning_htlc_subscription_history (
		id, lightning_node_id, payment_hash, invoice, final_amount_msat,
		receiver_mailbox_id, status, accepted_at, user_agent, created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.invoice, OLD.final_amount_msat,
		OLD.receiver_mailbox_id, OLD.status, OLD.accepted_at, OLD.user_agent, OLD.created_at, OLD.updated_at
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
