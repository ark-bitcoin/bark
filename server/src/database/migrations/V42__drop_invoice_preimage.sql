-- Copy any preimages from lightning_invoice into htlc_settlement
-- so no data is lost. ON CONFLICT ensures we don't duplicate entries
-- that are already in the settlement table.
INSERT INTO htlc_settlement (payment_hash, preimage, created_at)
SELECT payment_hash, preimage, updated_at
FROM lightning_invoice
WHERE preimage IS NOT NULL
ON CONFLICT (payment_hash) DO NOTHING;

-- Drop the preimage column from the invoice table.
ALTER TABLE lightning_invoice DROP COLUMN preimage;

-- Recreate the update trigger without the preimage column.
-- The history table keeps its preimage column for recovery purposes,
-- but new history rows will have NULL preimage since the invoice table
-- no longer carries it.
CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger() RETURNS TRIGGER AS $$
BEGIN
	INSERT INTO lightning_invoice_history (
		id, invoice, payment_hash, final_amount_msat,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat,
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
