-- Every update used to write a history record and bump updated_at, even
-- when nothing else changed. Idempotent updates (e.g. re-marking a VTXO as
-- spent by the same tx) then filled the history tables with duplicates.
-- The triggers now skip both for such no-op updates. The row itself is
-- still rewritten: they return OLD rather than NULL so the update still
-- counts the row, which callers rely on to check that all rows matched.

CREATE OR REPLACE FUNCTION integration_api_key_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
    new_updated_at integration_api_key.updated_at%TYPE := NEW.updated_at;
BEGIN
    -- An update that changes nothing but updated_at is a no-op: don't bump
    -- updated_at and don't write a history record for it.
    NEW.updated_at := OLD.updated_at;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := new_updated_at;

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
$$;

CREATE OR REPLACE FUNCTION integration_token_config_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
    new_updated_at integration_token_config.updated_at%TYPE := NEW.updated_at;
BEGIN
    -- An update that changes nothing but updated_at is a no-op: don't bump
    -- updated_at and don't write a history record for it.
    NEW.updated_at := OLD.updated_at;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := new_updated_at;

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
$$;

CREATE OR REPLACE FUNCTION integration_token_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
    new_updated_at integration_token.updated_at%TYPE := NEW.updated_at;
BEGIN
    -- An update that changes nothing but updated_at is a no-op: don't bump
    -- updated_at and don't write a history record for it.
    NEW.updated_at := OLD.updated_at;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := new_updated_at;

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
$$;

CREATE OR REPLACE FUNCTION lightning_htlc_subscription_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
	new_updated_at lightning_htlc_subscription.updated_at%TYPE := NEW.updated_at;
BEGIN
	-- An update that changes nothing but updated_at is a no-op: don't bump
	-- updated_at and don't write a history record for it.
	NEW.updated_at := OLD.updated_at;
	IF NEW IS NOT DISTINCT FROM OLD THEN
		RETURN OLD;
	END IF;
	NEW.updated_at := new_updated_at;

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

CREATE OR REPLACE FUNCTION lightning_invoice_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
	new_updated_at lightning_invoice.updated_at%TYPE := NEW.updated_at;
BEGIN
	-- An update that changes nothing but updated_at is a no-op: don't bump
	-- updated_at and don't write a history record for it.
	NEW.updated_at := OLD.updated_at;
	IF NEW IS NOT DISTINCT FROM OLD THEN
		RETURN OLD;
	END IF;
	NEW.updated_at := new_updated_at;

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
$$;

CREATE OR REPLACE FUNCTION lightning_node_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
    new_updated_at lightning_node.updated_at%TYPE := NEW.updated_at;
BEGIN
    -- An update that changes nothing but updated_at is a no-op: don't bump
    -- updated_at and don't write a history record for it.
    NEW.updated_at := OLD.updated_at;
    IF NEW IS NOT DISTINCT FROM OLD THEN
        RETURN OLD;
    END IF;
    NEW.updated_at := new_updated_at;

    INSERT INTO lightning_node_history (
        id, pubkey, payment_created_index, payment_updated_index,
        created_at, updated_at
    ) VALUES (
        OLD.id, OLD.pubkey, OLD.payment_created_index, OLD.payment_updated_index,
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

CREATE OR REPLACE FUNCTION lightning_payment_attempt_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
	new_updated_at lightning_payment_attempt.updated_at%TYPE := NEW.updated_at;
BEGIN
	-- An update that changes nothing but updated_at is a no-op: don't bump
	-- updated_at and don't write a history record for it.
	NEW.updated_at := OLD.updated_at;
	IF NEW IS NOT DISTINCT FROM OLD THEN
		RETURN OLD;
	END IF;
	NEW.updated_at := new_updated_at;

	INSERT INTO lightning_payment_attempt_history (
		id, lightning_node_id, payment_hash, amount_msat, final_amount_msat,
		sender_mailbox_id, status, error,
		block_height, user_fee_sat, user_agent, retry_for_secs, max_routing_fee_msat,
		lightning_htlc_subscription_id,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.lightning_node_id, OLD.payment_hash, OLD.amount_msat, OLD.final_amount_msat,
		OLD.sender_mailbox_id, OLD.status, OLD.error,
		OLD.block_height, OLD.user_fee_sat, OLD.user_agent, OLD.retry_for_secs, OLD.max_routing_fee_msat,
		OLD.lightning_htlc_subscription_id,
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

CREATE OR REPLACE FUNCTION virtual_transaction_history_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
	new_updated_at virtual_transaction.updated_at%TYPE := NEW.updated_at;
BEGIN
	-- An update that changes nothing but updated_at is a no-op: don't bump
	-- updated_at and don't write a history record for it.
	NEW.updated_at := OLD.updated_at;
	IF NEW IS NOT DISTINCT FROM OLD THEN
		RETURN OLD;
	END IF;
	NEW.updated_at := new_updated_at;

	INSERT INTO virtual_transaction_history (
		txid, signed_tx, is_funding, created_at, updated_at
	) VALUES (
		OLD.txid, OLD.signed_tx, OLD.is_funding, OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at AND NEW.updated_at <> NOW() THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION vtxo_update_trigger() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
DECLARE
	new_updated_at vtxo.updated_at%TYPE := NEW.updated_at;
BEGIN
	-- An update that changes nothing but updated_at is a no-op: don't bump
	-- updated_at and don't write a history record for it.
	NEW.updated_at := OLD.updated_at;
	IF NEW IS NOT DISTINCT FROM OLD THEN
		RETURN OLD;
	END IF;
	NEW.updated_at := new_updated_at;

	INSERT INTO vtxo_history (
		id, vtxo_id, vtxo_txid, vtxo, expiry, exit_delta, policy_type, policy,
		server_pubkey, amount, anchor_point,
		oor_spent_txid, spent_in_round, offboarded_in,
		lightning_htlc_subscription_id, banned_until_height,
		spend_state,
		frontier_at, confirmed_height, onchain_spent_height, onchain_spent_txid,
		created_at, updated_at
	) VALUES (
		OLD.id, OLD.vtxo_id, OLD.vtxo_txid, OLD.vtxo, OLD.expiry, OLD.exit_delta, OLD.policy_type, OLD.policy,
		OLD.server_pubkey, OLD.amount, OLD.anchor_point,
		OLD.oor_spent_txid, OLD.spent_in_round, OLD.offboarded_in,
		OLD.lightning_htlc_subscription_id, OLD.banned_until_height,
		OLD.spend_state,
		OLD.frontier_at, OLD.confirmed_height, OLD.onchain_spent_height, OLD.onchain_spent_txid,
		OLD.created_at, OLD.updated_at
	);

	IF NEW.updated_at = OLD.updated_at AND new.updated_at <> NOW() THEN
		RAISE EXCEPTION 'updated_at must be updated';
	END IF;

	IF NEW.created_at <> OLD.created_at THEN
		RAISE EXCEPTION 'created_at cannot be updated';
	END IF;

	RETURN NEW;
END;
$$;
