
CREATE TABLE lightning_node (
  lightning_node_id BIGSERIAL NOT NULL PRIMARY KEY,
  public_key BYTEA NOT NULL,
  payment_created_index BIGINT NOT NULL,
  payment_updated_index BIGINT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX lightning_node_public_key_uix ON lightning_node(public_key);

CREATE TABLE lightning_node_history (
  lightning_node_id BIGINT NOT NULL,
  public_key BYTEA NOT NULL,
  payment_created_index BIGINT NOT NULL,
  payment_updated_index BIGINT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION lightning_node_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO lightning_node_history (
    lightning_node_id, public_key, payment_created_index, payment_updated_index,
    created_at, updated_at
  ) VALUES (
    OLD.lightning_node_id, OLD.public_key, OLD.payment_created_index, OLD.payment_updated_index,
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

CREATE TRIGGER lightning_node_update
    BEFORE UPDATE ON lightning_node
    FOR EACH ROW
EXECUTE FUNCTION lightning_node_update_trigger();


CREATE TYPE lightning_payment_status AS ENUM('requested', 'submitted', 'succeeded', 'failed');

CREATE TABLE lightning_invoice (
  lightning_invoice_id BIGSERIAL NOT NULL PRIMARY KEY,
  invoice TEXT NOT NULL,
  payment_hash BYTEA NOT NULL,
  final_amount_msat BIGINT,
  preimage BYTEA,
  payment_status lightning_payment_status NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE UNIQUE INDEX lightning_invoice_invoice_uix ON lightning_invoice(invoice) INCLUDE (lightning_invoice_id);
CREATE UNIQUE INDEX lightning_payment_hash_uix ON lightning_invoice(payment_hash) INCLUDE (lightning_invoice_id);
CREATE INDEX lightning_payment_status_ix ON lightning_invoice(payment_status, lightning_invoice_id);

CREATE TABLE lightning_invoice_history (
  lightning_invoice_id BIGINT NOT NULL,
  invoice TEXT NOT NULL,
  payment_hash BYTEA NOT NULL,
  final_amount_msat BIGINT,
  preimage BYTEA,
  payment_status lightning_payment_status NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO lightning_invoice_history (
    lightning_invoice_id, invoice, payment_hash, final_amount_msat, preimage, payment_status,
    created_at, updated_at
  ) VALUES (
    OLD.lightning_invoice_id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
	OLD.payment_status, OLD.created_at, OLD.updated_at
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


CREATE TABLE lightning_payment_attempt (
  lightning_payment_attempt_id BIGSERIAL NOT NULL PRIMARY KEY,
  lightning_invoice_id BIGINT NOT NULL REFERENCES lightning_invoice(lightning_invoice_id),
  lightning_node_id BIGINT NOT NULL REFERENCES lightning_node(lightning_node_id),
  amount_msat BIGINT NOT NULL,
  status lightning_payment_status NOT NULL,
  error TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX lightning_payment_attempt_status_ix ON
    lightning_payment_attempt(status, lightning_node_id, lightning_invoice_id);

CREATE TABLE lightning_payment_attempt_history (
  lightning_payment_attempt_id BIGINT NOT NULL,
  lightning_invoice_id BIGINT NOT NULL,
  lightning_node_id BIGINT NOT NULL,
  amount_msat BIGINT NOT NULL,
  status lightning_payment_status NOT NULL,
  error TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
  history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO lightning_payment_attempt_history (
    lightning_payment_attempt_id, lightning_invoice_id, lightning_node_id, amount_msat,
	status, error, created_at, updated_at
  ) VALUES (
    OLD.lightning_payment_attempt_id, OLD.lightning_invoice_id, OLD.lightning_node_id, 
	OLD.amount_msat, OLD.status, OLD.error, OLD.created_at, OLD.updated_at
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

CREATE TRIGGER lightning_payment_attempt_update
    BEFORE UPDATE ON lightning_payment_attempt
    FOR EACH ROW
EXECUTE FUNCTION lightning_payment_attempt_update_trigger();
