DROP INDEX lightning_payment_status_ix;

ALTER TABLE lightning_invoice DROP COLUMN payment_status;

ALTER TABLE lightning_invoice_history DROP COLUMN payment_status;

CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO lightning_invoice_history (
    lightning_invoice_id, invoice, payment_hash, final_amount_msat, preimage,
    created_at, updated_at
  ) VALUES (
    OLD.lightning_invoice_id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
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
