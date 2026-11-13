-- Match VtxoInserts::owned_vtxo_ids for known states and policies. The
-- first byte is the protocol policy tag (currently 0x00 through 0x0b).
-- Unknown states and tags require a binding until explicitly classified.
CREATE FUNCTION vtxo_requires_owner_mailbox(state spend_state, policy BYTEA)
RETURNS BOOLEAN LANGUAGE SQL IMMUTABLE STRICT
RETURN CASE
	WHEN state IN ('spent', 'pool', 'ln-spent', 'round-forfeit', 'offboard-forfeit', 'offboard-connector') THEN FALSE
	WHEN octet_length(policy) = 0 THEN TRUE
	WHEN get_byte(policy, 0) > 11 THEN TRUE
	WHEN state IN ('spendable', 'unregistered', 'unclaimed', 'htlc-recv-unclaimed') THEN NOT (
		policy = '\x07'::BYTEA -- server-owned
		OR (get_byte(policy, 0) = 4 AND octet_length(policy) = 33) -- expiry
		OR (state = 'unclaimed' AND policy = -- round padding pubkey policy
			'\x0002dfa52f6690299d2d6a08323083e290597b56fee125063e5f4e2957731639c42c'::BYTEA)
	)
	ELSE TRUE
END;

CREATE FUNCTION require_vtxo_owner_mailbox() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
	payouts BOOLEAN;
BEGIN
	SELECT expiry_payouts INTO STRICT payouts FROM server_mode WHERE id = 1;
	IF payouts AND NOT EXISTS (SELECT 1 FROM vtxo_owner_mailbox WHERE vtxo_id = NEW.vtxo_id) THEN
		RAISE EXCEPTION 'VTXO % has no owner mailbox', NEW.vtxo_id
			USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'vtxo_require_owner_mailbox';
	END IF;
	RETURN NULL;
END;
$$;

-- Queue the check from the row as written, even if it becomes spent
-- later in this transaction. The binding itself may be inserted later.
CREATE CONSTRAINT TRIGGER vtxo_require_owner_mailbox
AFTER INSERT OR UPDATE OF vtxo_id, spend_state, policy ON vtxo
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
WHEN (vtxo_requires_owner_mailbox(NEW.spend_state, NEW.policy))
EXECUTE FUNCTION require_vtxo_owner_mailbox();

-- A binding remains relevant after spending, for example when the
-- watchman refunds an unregistered arkoor to its input owner.
CREATE FUNCTION preserve_vtxo_owner_mailbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
	RAISE EXCEPTION 'VTXO owner mailbox bindings are immutable'
		USING ERRCODE = 'integrity_constraint_violation';
END;
$$;

CREATE TRIGGER vtxo_owner_mailbox_immutable
BEFORE UPDATE OR DELETE ON vtxo_owner_mailbox FOR EACH ROW
EXECUTE FUNCTION preserve_vtxo_owner_mailbox();

CREATE TRIGGER vtxo_owner_mailbox_no_truncate
BEFORE TRUNCATE ON vtxo_owner_mailbox FOR EACH STATEMENT
EXECUTE FUNCTION preserve_vtxo_owner_mailbox();

-- Existing held rows are not checked by a newly installed constraint
-- trigger. Refuse to upgrade a payout database that already has gaps.
DO $$
DECLARE
	missing_count BIGINT;
BEGIN
	IF (SELECT expiry_payouts FROM server_mode WHERE id = 1) THEN
		SELECT count(*) INTO missing_count
		FROM vtxo AS v
		WHERE vtxo_requires_owner_mailbox(v.spend_state, v.policy)
			AND NOT EXISTS (SELECT 1 FROM vtxo_owner_mailbox AS o WHERE o.vtxo_id = v.vtxo_id);
		IF missing_count > 0 THEN
			RAISE EXCEPTION '% owner-held VTXOs have no owner mailbox binding', missing_count;
		END IF;
	END IF;
END;
$$;
