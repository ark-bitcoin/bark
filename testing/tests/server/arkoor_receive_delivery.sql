-- Run against a newly migrated server database. Both invoices pay the same
-- amount to the same key. The first uses a checkpoint and has two outputs.
DO $test$
DECLARE
	merchant CONSTANT text := current_setting('receipt_test.merchant');
	merchant_policy CONSTANT bytea := decode(current_setting('receipt_test.policy'), 'hex');
	box CONSTANT text := '02' || repeat('11', 32);
	server_key CONSTANT text := '02' || repeat('22', 32);
	node_id bigint;
	payout_id bigint;
BEGIN
	INSERT INTO lightning_node (pubkey, payment_created_index, payment_updated_index, created_at, updated_at)
		VALUES (decode(server_key, 'hex'), 0, 0, now(), now()) RETURNING id INTO node_id;
	INSERT INTO lightning_htlc_subscription (lightning_node_id, status, created_at, updated_at,
		payment_hash, invoice, receiver_mailbox_id, claim_pubkey, arkoor_input_ids)
	VALUES
		(node_id, 'settled', now(), now(), 'sale-1', 'invoice-1', box, merchant, ARRAY['in-1', 'in-2']),
		(node_id, 'settled', now(), now(), 'sale-2', 'invoice-2', box, merchant, ARRAY['in-3']);

	INSERT INTO vtxo (vtxo_id, vtxo_txid, oor_spent_txid, policy_type, amount, spend_state,
		policy, vtxo, expiry, exit_delta, server_pubkey, anchor_point, created_at, updated_at)
	SELECT id, tx, spend, kind, sats, state::spend_state,
		CASE WHEN key = merchant THEN merchant_policy ELSE '\x02'::bytea END,
		'\x01', 200, 10, server_key, 'anchor', now(), now()
	FROM (VALUES
		('in-1', 'fund-1', 'tx-1', 'pubkey', 15000, 'spent', server_key),
		('in-2', 'fund-2', 'tx-2', 'pubkey', 20000, 'spent', server_key),
		('in-3', 'fund-3', 'tx-3', 'pubkey', 40000, 'spent', server_key),
		('step', 'tx-1', 'final', 'checkpoint', 15000, 'spent', server_key),
		('a', 'final', NULL, 'pubkey', 15000, 'spendable', merchant),
		('b', 'tx-2', NULL, 'pubkey', 20000, 'unregistered', merchant),
		('c', 'tx-3', NULL, 'pubkey', 35000, 'spendable', merchant),
		('change', 'tx-3', NULL, 'pubkey', 5000, 'spendable', server_key),
		('unrelated', 'other', NULL, 'pubkey', 35000, 'spendable', merchant)
	) AS data(id, tx, spend, kind, sats, state, key);

	INSERT INTO arkoor_receive_output (subscription_id, vtxo_id)
		SELECT s.id, o.vtxo_id FROM (VALUES ('sale-1','a'), ('sale-1','b'), ('sale-2','c')) o(hash,vtxo_id)
		JOIN lightning_htlc_subscription s ON s.payment_hash = o.hash;

	INSERT INTO vtxo_owner_mailbox (vtxo_id, mailbox_pk)
		SELECT id, box FROM unnest(ARRAY['a','b','c','unrelated']) AS id;
	INSERT INTO mailbox (unblinded_mailbox_id, vtxo_id, vtxo, checkpoint, created_at, mailbox_type)
		SELECT box, id, '\x01', 1, now(), 'arkoor-receive' FROM unnest(ARRAY['a','c','unrelated']) AS id;

	BEGIN
		PERFORM verify_arkoor_receive_outputs(ARRAY['c']);
		RAISE EXCEPTION 'certification without a chain tip must be retried';
	EXCEPTION WHEN no_data_found THEN NULL;
	END;
	INSERT INTO captaind_block (height, hash) VALUES (100, repeat('0', 64));
	PERFORM verify_arkoor_receive_outputs(ARRAY['a','b','c','unrelated']);

	IF (SELECT count(*) FROM v_arkoor_receive_delivery) <> 1 OR NOT EXISTS (
		SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-2'
			AND claim_pubkey = merchant AND receiver_mailbox_id = box AND server_pubkey = server_key
			AND amount_sat = 35000 AND vtxo_ids = ARRAY['c'] AND expiry_height = 200
	) THEN RAISE EXCEPTION 'only sale 2 has a complete delivery'; END IF;

	-- The checkout applies its own sale price and retains the amount received.
	IF (SELECT amount_sat FROM v_arkoor_receive_delivery
		WHERE payment_hash = 'sale-2' AND amount_sat >= 34000) IS DISTINCT FROM 35000
		OR EXISTS (SELECT 1 FROM v_arkoor_receive_delivery
			WHERE payment_hash = 'sale-2' AND amount_sat >= 36000)
		THEN RAISE EXCEPTION 'credit excess value and keep an underpaid sale open'; END IF;

	-- The first split output can be spent while its sibling is in flight.
	UPDATE vtxo SET spend_state = 'spent' WHERE vtxo_id = 'a';
	INSERT INTO mailbox (unblinded_mailbox_id, vtxo_id, vtxo, checkpoint, created_at, mailbox_type)
		VALUES (server_key, 'b', '\x01', 2, now(), 'arkoor-receive');
	PERFORM verify_arkoor_receive_outputs(ARRAY['b']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-1')
		THEN RAISE EXCEPTION 'an unregistered output cannot complete sale 1'; END IF;
	UPDATE vtxo SET spend_state = 'spendable' WHERE vtxo_id = 'b';
	PERFORM verify_arkoor_receive_outputs(ARRAY['b']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-1')
		THEN RAISE EXCEPTION 'a post to another mailbox cannot complete sale 1'; END IF;
	UPDATE mailbox SET unblinded_mailbox_id = box, vtxo = '\x02' WHERE vtxo_id = 'b';
	PERFORM verify_arkoor_receive_outputs(ARRAY['b']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-1')
		THEN RAISE EXCEPTION 'the signed bytes must match'; END IF;
	UPDATE mailbox SET vtxo = '\x01' WHERE vtxo_id = 'b';
	UPDATE vtxo_owner_mailbox SET mailbox_pk = server_key WHERE vtxo_id = 'b';
	PERFORM verify_arkoor_receive_outputs(ARRAY['b']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-1')
		THEN RAISE EXCEPTION 'every output must belong to the enrolled mailbox'; END IF;
	UPDATE vtxo_owner_mailbox SET mailbox_pk = box WHERE vtxo_id = 'b';
	UPDATE vtxo SET banned_until_height = 101 WHERE vtxo_id = 'b';
	PERFORM verify_arkoor_receive_outputs(ARRAY['b']);
	IF NOT EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash = 'sale-1'
		AND amount_sat = 35000 AND vtxo_ids = ARRAY['a','b'])
		THEN RAISE EXCEPTION 'a round ban must not delay delivery, and the spent sibling must still count'; END IF;

	UPDATE vtxo SET spend_state = 'spent', oor_spent_txid = 'other' WHERE vtxo_id = 'c';
	INSERT INTO expiry_payout (expiry_height) VALUES (200) RETURNING id INTO payout_id;
	INSERT INTO expiry_payout_vtxo (expiry_payout_id, vtxo_id, disposition, gross_sat, fee_sat, payout_sat, replannable)
		VALUES (payout_id, 'a', 'operator', 15000, 0, 0, false);
	PERFORM verify_arkoor_receive_outputs(ARRAY['a','b','c']);
	IF (SELECT count(*) FROM v_arkoor_receive_delivery) <> 2
		THEN RAISE EXCEPTION 'retries, spends and later payout decisions must preserve receipts'; END IF;

	-- A payment first seen after a spend or payout has no historical proof.
	INSERT INTO lightning_htlc_subscription (lightning_node_id, status, created_at, updated_at,
		payment_hash, invoice, receiver_mailbox_id, claim_pubkey, arkoor_input_ids)
		VALUES (node_id, 'settled', now(), now(), 'late', 'invoice-3', box, merchant, ARRAY['unused']);
	INSERT INTO arkoor_receive_output (subscription_id, vtxo_id)
		SELECT id, 'unrelated' FROM lightning_htlc_subscription WHERE payment_hash='late';
	UPDATE vtxo SET spend_state='spent' WHERE vtxo_id='unrelated';
	PERFORM verify_arkoor_receive_outputs(ARRAY['unrelated']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash='late')
		THEN RAISE EXCEPTION 'later observation cannot certify a spent output'; END IF;
	UPDATE vtxo SET spend_state='spendable' WHERE vtxo_id='unrelated';
	INSERT INTO expiry_payout_vtxo (expiry_payout_id, vtxo_id, disposition, gross_sat, fee_sat, payout_sat, replannable)
		VALUES (payout_id, 'unrelated', 'operator', 35000, 0, 0, false);
	PERFORM verify_arkoor_receive_outputs(ARRAY['unrelated']);
	IF EXISTS (SELECT 1 FROM v_arkoor_receive_delivery WHERE payment_hash='late')
		THEN RAISE EXCEPTION 'a payout-decided output cannot start a receipt'; END IF;
END
$test$;
