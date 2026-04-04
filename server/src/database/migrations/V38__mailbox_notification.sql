-- Add lightning receive notification type to mailbox_type enum
ALTER TYPE mailbox_type ADD VALUE 'ln-recv-pending';

-- Store client's mailbox ID on lightning invoices
ALTER TABLE lightning_invoice ADD COLUMN mailbox_id TEXT;

DROP INDEX lightning_payment_hash_uix;
DROP TRIGGER lightning_invoice_update ON lightning_invoice;
DROP FUNCTION lightning_invoice_update_trigger;

ALTER TABLE lightning_invoice ALTER COLUMN payment_hash TYPE TEXT USING encode(payment_hash, 'hex');
ALTER TABLE lightning_invoice ALTER COLUMN preimage TYPE TEXT USING encode(preimage, 'hex');

ALTER TABLE lightning_invoice_history ALTER COLUMN payment_hash TYPE TEXT USING encode(payment_hash, 'hex');
ALTER TABLE lightning_invoice_history ALTER COLUMN preimage TYPE TEXT USING encode(preimage, 'hex');

ALTER TABLE htlc_settlement ALTER COLUMN preimage TYPE TEXT USING encode(preimage, 'hex');
ALTER TABLE round_participation ALTER COLUMN unlock_preimage TYPE TEXT USING encode(unlock_preimage, 'hex');

CREATE UNIQUE INDEX lightning_payment_hash_uix ON lightning_invoice(payment_hash) INCLUDE (id);

CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_invoice_history (
        id, invoice, payment_hash, final_amount_msat, preimage,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
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

CREATE TRIGGER lightning_invoice_update
    BEFORE UPDATE ON lightning_invoice
    FOR EACH ROW
    EXECUTE FUNCTION lightning_invoice_update_trigger();
