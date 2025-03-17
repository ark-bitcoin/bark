CREATE TYPE lightning_htlc_subscription_status AS ENUM('created', 'accepted', 'settled', 'cancelled');

CREATE TABLE lightning_htlc_subscription (
  lightning_htlc_subscription_id BIGSERIAL NOT NULL PRIMARY KEY,
  lightning_invoice_id BIGINT NOT NULL REFERENCES lightning_invoice(lightning_invoice_id),
  lightning_node_id BIGINT NOT NULL REFERENCES lightning_node(lightning_node_id),
  status lightning_htlc_subscription_status NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX lightning_htlc_subscription_status_ix ON
    lightning_htlc_subscription(status, lightning_node_id, lightning_invoice_id);

CREATE TABLE lightning_htlc_subscription_history (
  lightning_htlc_subscription_id BIGINT NOT NULL,
  lightning_invoice_id BIGINT NOT NULL,
  lightning_node_id BIGINT NOT NULL,
  status lightning_htlc_subscription_status NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO lightning_htlc_subscription_history (
    lightning_htlc_subscription_id, lightning_invoice_id, lightning_node_id,
	status, created_at, updated_at
  ) VALUES (
    OLD.lightning_htlc_subscription_id, OLD.lightning_invoice_id, OLD.lightning_node_id,
	OLD.status, OLD.created_at, OLD.updated_at
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

CREATE TRIGGER lightning_htlc_subscription_update
    BEFORE UPDATE ON lightning_htlc_subscription
    FOR EACH ROW
EXECUTE FUNCTION lightning_htlc_subscription_update_trigger();