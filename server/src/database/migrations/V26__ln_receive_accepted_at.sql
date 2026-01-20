
--
-- add a column to record when the subscription was accepted
--

ALTER TABLE lightning_htlc_subscription ADD COLUMN accepted_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE lightning_htlc_subscription_history ADD COLUMN accepted_at TIMESTAMP WITH TIME ZONE;

-- Update the trigger function to include accepted_at
CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_htlc_subscription_history (
        id, lightning_invoice_id, lightning_node_id,
        status, accepted_at, created_at, updated_at
    ) VALUES (
        OLD.id, OLD.lightning_invoice_id, OLD.lightning_node_id,
        OLD.status, OLD.accepted_at, OLD.created_at, OLD.updated_at
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
