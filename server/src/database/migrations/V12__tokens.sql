
CREATE TABLE integration (
    integration_id BIGSERIAL NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX integration_name_uix ON integration(name);

CREATE TABLE integration_api_key (
    integration_api_key_id BIGSERIAL NOT NULL PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL,
    filters TEXT,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX integration_api_key_api_key_uix ON integration_api_key(api_key);
CREATE UNIQUE INDEX integration_api_key_name_uix ON integration_api_key(integration_id, name);

CREATE TABLE integration_api_key_history (
    integration_api_key_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    api_key TEXT NOT NULL,
    filters TEXT,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE,
    history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION integration_api_key_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_api_key_history (
        integration_api_key_id, name, api_key, filters, integration_id, expires_at,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.integration_api_key_id, OLD.name, OLD.api_key, OLD.filters, OLD.integration_id, OLD.expires_at,
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


CREATE TYPE token_type AS ENUM('single-use-board');

CREATE TABLE integration_token_config (
    integration_token_config_id BIGSERIAL NOT NULL PRIMARY KEY,
    type token_type NOT NULL,
    maximum_open_tokens INTEGER NOT NULL,
    active_seconds INTEGER NOT NULL,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE UNIQUE INDEX integration_token_config_uix ON integration_token_config(type, integration_id);

CREATE TABLE integration_token_config_history (
    integration_token_config_id BIGINT NOT NULL,
    type token_type NOT NULL,
    maximum_open_tokens INTEGER NOT NULL,
    active_seconds INTEGER NOT NULL,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE,
    history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION integration_token_config_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_token_config_history (
        integration_token_config_id, type, maximum_open_tokens, active_seconds,
        integration_id,
        created_at, updated_at, deleted_at
    ) VALUES (
        OLD.integration_token_config_id, OLD.type, OLD.maximum_open_tokens, OLD.active_seconds,
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


CREATE TYPE token_status AS ENUM('unused', 'used', 'abused', 'disabled');

CREATE TABLE integration_token (
    integration_token_id BIGSERIAL NOT NULL PRIMARY KEY,
    token TEXT NOT NULL,
    type token_type NOT NULL,
    status token_status NOT NULL,
    filters TEXT,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by_api_key_id BIGINT NOT NULL REFERENCES integration_api_key(integration_api_key_id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_by_api_key_id BIGINT NOT NULL REFERENCES integration_api_key(integration_api_key_id)
);

CREATE UNIQUE INDEX integration_token_token_uix ON integration_token(token);
CREATE INDEX integration_token_status_expires_at_ix ON integration_token(status, expires_at);
CREATE INDEX integration_token_type_status_integration_expires_at_ix ON integration_token(type, status, integration_id, expires_at);

CREATE TABLE integration_token_history (
    integration_token_id BIGINT NOT NULL,
    token TEXT NOT NULL,
    type token_type NOT NULL,
    status token_status NOT NULL,
    filters TEXT,
    integration_id BIGINT NOT NULL REFERENCES integration(integration_id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_by_api_key_id BIGINT NOT NULL REFERENCES integration_api_key(integration_api_key_id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_by_api_key_id BIGINT NOT NULL REFERENCES integration_api_key(integration_api_key_id),
    history_created_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP AT TIME ZONE 'UTC') NOT NULL
);

CREATE OR REPLACE FUNCTION integration_token_update_trigger()
  RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO integration_token_history (
        integration_token_id, token, type, status, filters, integration_id,
        expires_at,
        created_at, created_by_api_key_id, updated_at, updated_by_api_key_id
    ) VALUES (
        OLD.integration_token_id, OLD.token, OLD.type, OLD.status, OLD.filters, OLD.integration_id,
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

