-- Add a lightning send finished notification type to mailbox_type enum
ALTER TYPE mailbox_type ADD VALUE 'ln-send-finished';

-- Add a column for preimage (used by ln-send-finished, present only on success)
ALTER TABLE mailbox ADD COLUMN preimage TEXT;

CREATE UNIQUE INDEX mailbox_mailbox_type_payment_hash_uix ON mailbox (mailbox_type, payment_hash);

-- Add lightning_invoice columns to lightning_payment_attempt (send side)
ALTER TABLE lightning_payment_attempt ADD COLUMN payment_hash TEXT;
ALTER TABLE lightning_payment_attempt ADD COLUMN final_amount_msat BIGINT;
ALTER TABLE lightning_payment_attempt ADD COLUMN sender_mailbox_id TEXT;

-- Add lightning_invoice columns to lightning_htlc_subscription (receive side)
ALTER TABLE lightning_htlc_subscription ADD COLUMN payment_hash TEXT;
ALTER TABLE lightning_htlc_subscription ADD COLUMN invoice TEXT;
ALTER TABLE lightning_htlc_subscription ADD COLUMN final_amount_msat BIGINT;
ALTER TABLE lightning_htlc_subscription ADD COLUMN receiver_mailbox_id TEXT;

-- Migrate data from lightning_invoice to lightning_payment_attempt
UPDATE lightning_payment_attempt attempt
SET payment_hash = invoice.payment_hash,
	final_amount_msat = invoice.final_amount_msat
FROM lightning_invoice invoice
WHERE attempt.lightning_invoice_id = invoice.id;

-- Migrate data from lightning_invoice to lightning_htlc_subscription
UPDATE lightning_htlc_subscription sub
SET payment_hash = invoice.payment_hash,
	invoice = invoice.invoice,
	final_amount_msat = invoice.final_amount_msat,
	receiver_mailbox_id = invoice.mailbox_id
FROM lightning_invoice invoice
WHERE sub.lightning_invoice_id = invoice.id;

-- Set NOT NULL constraints after migration
ALTER TABLE lightning_payment_attempt ALTER COLUMN payment_hash SET NOT NULL;
ALTER TABLE lightning_htlc_subscription ALTER COLUMN payment_hash SET NOT NULL;
ALTER TABLE lightning_htlc_subscription ALTER COLUMN invoice SET NOT NULL;

-- Add indexes for payment_hash lookups and status filtering
CREATE INDEX lightning_payment_attempt_payment_hash_ix
	ON lightning_payment_attempt(payment_hash);
CREATE INDEX lightning_payment_attempt_status_node_ix
	ON lightning_payment_attempt(status, lightning_node_id);
CREATE UNIQUE INDEX lightning_payment_attempt_open_payment_hash_uix
	ON lightning_payment_attempt(payment_hash)
	WHERE status NOT IN ('failed', 'succeeded');
CREATE INDEX lightning_htlc_subscription_payment_hash_ix
	ON lightning_htlc_subscription(payment_hash);
CREATE INDEX lightning_htlc_subscription_status_node_ix
	ON lightning_htlc_subscription(status, lightning_node_id);

-- Drop the foreign key columns
ALTER TABLE lightning_payment_attempt DROP COLUMN lightning_invoice_id;
ALTER TABLE lightning_htlc_subscription DROP COLUMN lightning_invoice_id;

-- Update history tables: drop lightning_invoice_id, add new columns
ALTER TABLE lightning_payment_attempt_history DROP COLUMN lightning_invoice_id;
ALTER TABLE lightning_payment_attempt_history ADD COLUMN payment_hash TEXT;
ALTER TABLE lightning_payment_attempt_history ADD COLUMN final_amount_msat BIGINT;
ALTER TABLE lightning_payment_attempt_history ADD COLUMN sender_mailbox_id TEXT;

ALTER TABLE lightning_htlc_subscription_history DROP COLUMN lightning_invoice_id;
ALTER TABLE lightning_htlc_subscription_history ADD COLUMN payment_hash TEXT;
ALTER TABLE lightning_htlc_subscription_history ADD COLUMN invoice TEXT;
ALTER TABLE lightning_htlc_subscription_history ADD COLUMN final_amount_msat BIGINT;
ALTER TABLE lightning_htlc_subscription_history ADD COLUMN receiver_mailbox_id TEXT;

-- Recreate update triggers with the new columns
CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error, created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error, OLD.created_at, OLD.updated_at
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

CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger() RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO lightning_htlc_subscription_history (
		id, lightning_node_id, payment_hash, invoice, final_amount_msat,
		receiver_mailbox_id, status, accepted_at, created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.invoice, OLD.final_amount_msat,
		OLD.receiver_mailbox_id, OLD.status, OLD.accepted_at, OLD.created_at, OLD.updated_at
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
