DROP VIEW arkoor_mailbox;
DROP VIEW pending_sweep;
DROP VIEW round;
DROP VIEW vtxo;

DROP TABLE all_arkoor_mailbox;
DROP TABLE all_pending_sweep;
DROP TABLE all_round;
DROP TABLE all_vtxo;

CREATE TABLE round (
    id BIGSERIAL PRIMARY KEY,
    seq BIGINT NOT NULL,
    funding_txid TEXT NOT NULL,
    funding_tx BYTEA NOT NULL,
    signed_tree BYTEA NOT NULL,
    nb_input_vtxos INTEGER NOT NULL,
    connector_key BYTEA NOT NULL,
    expiry INTEGER NOT NULL,
    swept_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX round_tx_id_ix ON round (funding_txid, (swept_at IS NULL));
CREATE INDEX round_expiry_ix ON round (expiry, (swept_at IS NULL), funding_txid);

CREATE TABLE vtxo (
    id BIGSERIAL PRIMARY KEY,
    vtxo_id TEXT NOT NULL,
    vtxo BYTEA NOT NULL,
    expiry INTEGER NOT NULL,
    oor_spent_txid TEXT,
    forfeit_state BYTEA,
    forfeit_round_id BIGINT REFERENCES round(id),
    board_swept_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX vtxo_board_not_swept_expiry_ix ON vtxo ((board_swept_at IS NULL), expiry, vtxo_id);
CREATE INDEX vtxo_has_forfeit_state_ix ON vtxo ((forfeit_state IS NOT NULL), vtxo_id);
CREATE INDEX vtxo_spendable_ix ON vtxo ((oor_spent_txid IS NULL), (forfeit_state IS NULL), vtxo_id);

CREATE TABLE vtxo_history (
    id BIGINT NOT NULL,
    vtxo_id TEXT NOT NULL,
    vtxo BYTEA NOT NULL,
    expiry INTEGER NOT NULL,
    oor_spent_txid TEXT,
    forfeit_state BYTEA,
    forfeit_round_id BIGINT,
    board_swept_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION vtxo_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO vtxo_history (
        id, vtxo_id, vtxo, expiry, oor_spent_txid, forfeit_state, forfeit_round_id, board_swept_at,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.vtxo_id, OLD.vtxo, OLD.expiry, OLD.oor_spent_txid, OLD.forfeit_state, OLD.forfeit_round_id, OLD.board_swept_at,
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

CREATE TRIGGER vtxo_update
    BEFORE UPDATE ON vtxo
    FOR EACH ROW
    EXECUTE FUNCTION vtxo_update_trigger();


CREATE TABLE sweep (
    id BIGSERIAL PRIMARY KEY,
    txid TEXT NOT NULL,
    tx BYTEA NOT NULL,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    abandoned_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX sweep_tx_id_pending_ix ON sweep (txid, (abandoned_at IS NULL), (confirmed_at IS NULL));

CREATE TABLE arkoor_mailbox (
    id BIGSERIAL PRIMARY KEY,
    public_key BYTEA NOT NULL,
    vtxo_id BIGINT NOT NULL REFERENCES vtxo(id),
    vtxo BYTEA NOT NULL,
    arkoor_package_id BYTEA NOT NULL,
    processed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX arkoor_mailbox_public_key_ix ON arkoor_mailbox (public_key, (processed_at IS NULL));

DROP TABLE forfeits_claim_state;
-- CREATE TABLE forfeits_claim_state (
--     id BIGSERIAL PRIMARY KEY,
--     vtxo_id BIGINT NOT NULL REFERENCES vtxo(id),
--     connector_tx BYTEA,
--     connector_cpfp BYTEA,
--     connector_point BYTEA NOT NULL,
--     forfeit_tx BYTEA NOT NULL,
--     forfeit_cpfp BYTEA,
--     created_at TIMESTAMP WITH TIME ZONE NOT NULL
-- );

DROP TABLE forfeits_round_state;
-- CREATE TABLE forfeits_round_state (
--     id BIGSERIAL PRIMARY KEY,
--     round_id BIGINT NOT NULL REFERENCES round(id),
--     nb_connectors_used INTEGER NOT NULL,
--     created_at TIMESTAMP WITH TIME ZONE NOT NULL
-- );

DROP TABLE forfeits_wallet_changeset;
DROP TABLE wallet_changeset;
CREATE TYPE wallet_kind AS ENUM ('rounds', 'forfeits');
CREATE TABLE wallet_changeset (
    id BIGSERIAL PRIMARY KEY,
    kind wallet_kind NOT NULL,
    content BYTEA,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX wallet_changeset_kind_ix ON wallet_changeset (kind);


ALTER TABLE integration RENAME COLUMN integration_id TO id;

DROP TRIGGER integration_api_key_update;
DROP FUNCTION integration_api_key_update_trigger;
ALTER TABLE integration_api_key RENAME COLUMN integration_api_key_id TO id;
ALTER TABLE integration_api_key_history RENAME COLUMN integration_api_key_id TO id;

DROP TRIGGER integration_token_config_update;
DROP FUNCTION integration_token_config_update_trigger;
ALTER TABLE integration_token RENAME COLUMN integration_token_id TO id;
ALTER TABLE integration_token_history RENAME COLUMN integration_token_id TO id;

DROP TRIGGER integration_token_update;
DROP FUNCTION integration_token_update_trigger;
ALTER TABLE integration_token_config RENAME COLUMN integration_token_config_id TO id;
ALTER TABLE integration_token_config_history RENAME COLUMN integration_token_config_id TO id;

DROP TRIGGER lightning_htlc_subscription_update;
DROP FUNCTION lightning_htlc_subscription_update_trigger;
ALTER TABLE lightning_htlc_subscription RENAME COLUMN lightning_htlc_subscription_id TO id;
ALTER TABLE lightning_htlc_subscription_history RENAME COLUMN lightning_htlc_subscription_id TO id;

DROP TRIGGER lightning_invoice_update;
DROP FUNCTION lightning_invoice_update_trigger;
ALTER TABLE lightning_invoice RENAME COLUMN lightning_invoice_id TO id;
ALTER TABLE lightning_invoice_history RENAME COLUMN lightning_invoice_id TO id;

DROP TRIGGER lightning_node_update;
DROP FUNCTION lightning_node_update_trigger;
ALTER TABLE lightning_node RENAME COLUMN lightning_node_id TO id;
ALTER TABLE lightning_node_history RENAME COLUMN lightning_node_id TO id;

DROP TRIGGER lightning_payment_attempt_update;
DROP FUNCTION lightning_payment_attempt_update_trigger;
ALTER TABLE lightning_payment_attempt RENAME COLUMN lightning_payment_attempt_id TO id;
ALTER TABLE lightning_payment_attempt_history RENAME COLUMN lightning_payment_attempt_id TO id;


CREATE OR REPLACE FUNCTION integration_api_key_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_api_key_history (
        id, name, api_key, filters, integration_id, expires_at,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.id, OLD.name, OLD.api_key, OLD.filters, OLD.integration_id, OLD.expires_at,
        OLD.created_at, OLD.updated_at, OLD.deleted_at
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

CREATE TRIGGER integration_api_key_update
    BEFORE UPDATE ON integration_api_key
    FOR EACH ROW
    EXECUTE FUNCTION integration_api_key_update_trigger();


CREATE OR REPLACE FUNCTION integration_token_config_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_token_config_history (
        id, type, maximum_open_tokens, active_seconds,
        integration_id,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.id, OLD.type, OLD.maximum_open_tokens, OLD.active_seconds,
        OLD.integration_id,
        OLD.created_at, OLD.updated_at, OLD.deleted_at
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

CREATE TRIGGER integration_token_config_update
    BEFORE UPDATE ON integration_token_config
    FOR EACH ROW
    EXECUTE FUNCTION integration_token_config_update_trigger();


CREATE OR REPLACE FUNCTION integration_token_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_token_history (
        id, token, type, status, filters, integration_id,
        expires_at,
        created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
    ) VALUES (
        OLD.id, OLD.token, OLD.type, OLD.status, OLD.filters, OLD.integration_id,
        OLD.expires_at,
        OLD.created_at, OLD.created_by_api_key_id, OLD.updated_at, OLD.updated_by_api_key_id
    );

    IF NEW.updated_at = OLD.updated_at THEN
        RAISE EXCEPTION 'updated_at must be updated';
    END IF;

    IF NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'created_at cannot be updated';
    END IF;

    IF NEW.created_by_api_key_id <> OLD.created_by_api_key_id THEN
        RAISE EXCEPTION 'created_by_api_key_id cannot be updated';
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER integration_token_update
    BEFORE UPDATE ON integration_token
    FOR EACH ROW
    EXECUTE FUNCTION integration_token_update_trigger();


CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_htlc_subscription_history (
        id, lightning_invoice_id, lightning_node_id,
        status, created_at, updated_at
    ) VALUES (
        OLD.id, OLD.lightning_invoice_id, OLD.lightning_node_id,
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


CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_invoice_history (
        id, invoice, payment_hash, final_amount_msat, preimage, payment_status,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.invoice, OLD.payment_hash, OLD.final_amount_msat, OLD.preimage,
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


CREATE OR REPLACE FUNCTION lightning_node_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_node_history (
        id, public_key, payment_created_index, payment_updated_index,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.public_key, OLD.payment_created_index, OLD.payment_updated_index,
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


CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger()
    RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO lightning_payment_attempt_history (
        id, lightning_invoice_id, lightning_node_id, amount_msat,
        status, error, created_at, updated_at
    ) VALUES (
        OLD.id, OLD.lightning_invoice_id, OLD.lightning_node_id,
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

-- round
-- vtxo
-- vtxo_history
-- sweep
-- arkoor_mailbox
-- wallet_changeset
-- integration
-- integration_api_key
-- integration_api_key_history
-- integration_token
-- integration_token_history
-- integration_token_config
-- integration_token_config_history
-- lightning_htlc_subscription
-- lightning_htlc_subscription_history
-- lightning_invoice
-- lightning_invoice_history
-- lightning_node
-- lightning_node_history
-- lightning_payment_attempt
-- lightning_payment_attempt_history
