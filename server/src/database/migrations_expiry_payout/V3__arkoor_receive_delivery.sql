-- The co-sign fixes the set of final outputs owed to the invoice. A verified
-- output stays delivered when its owner spends it or it reaches expiry.
CREATE TABLE arkoor_receive_output (
	vtxo_id TEXT PRIMARY KEY REFERENCES vtxo(vtxo_id),
	subscription_id BIGINT NOT NULL REFERENCES lightning_htlc_subscription(id),
	delivered_height BIGINT
);
CREATE INDEX arkoor_receive_output_subscription_idx ON arkoor_receive_output (subscription_id);

-- Registration and posting may arrive in either order, in separate concurrent
-- transactions. Match the vtxo_id lock order of guard_spend_changes, then
-- check both writes with a fresh READ COMMITTED snapshot.
CREATE FUNCTION verify_arkoor_receive_outputs(ids TEXT[]) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
	tip_height BIGINT;
BEGIN
	PERFORM v.vtxo_id FROM arkoor_receive_output r JOIN vtxo v USING (vtxo_id)
	WHERE r.vtxo_id = ANY(ids) AND r.delivered_height IS NULL
	ORDER BY v.vtxo_id FOR NO KEY UPDATE OF v;
	IF NOT FOUND THEN RETURN; END IF;

	-- Without a tip we cannot check expiry. Roll back so the caller can retry.
	SELECT height INTO STRICT tip_height FROM captaind_block ORDER BY height DESC LIMIT 1;
	UPDATE arkoor_receive_output r SET delivered_height = tip_height
	FROM vtxo v JOIN mailbox m ON m.vtxo_id = v.vtxo_id AND m.mailbox_type = 'arkoor-receive'
	JOIN vtxo_owner_mailbox o ON o.vtxo_id = v.vtxo_id AND o.mailbox_pk = m.unblinded_mailbox_id,
		lightning_htlc_subscription s
	WHERE r.vtxo_id = ANY(ids) AND r.delivered_height IS NULL AND r.vtxo_id = v.vtxo_id
		AND s.id = r.subscription_id AND s.status = 'settled' AND s.receiver_mailbox_id = o.mailbox_pk
		AND v.policy_type = 'pubkey' AND v.policy = decode('00' || s.claim_pubkey, 'hex')
		AND m.vtxo = v.vtxo AND v.spend_state = 'spendable' AND v.confirmed_height IS NULL
		AND v.expiry > tip_height
		AND NOT EXISTS (SELECT 1 FROM expiry_payout_vtxo p WHERE p.vtxo_id = v.vtxo_id);
END;
$$;

CREATE VIEW v_arkoor_receive_delivery AS
SELECT s.payment_hash, s.claim_pubkey, s.receiver_mailbox_id,
	min(v.server_pubkey) AS server_pubkey, sum(v.amount)::bigint AS amount_sat,
	array_agg(r.vtxo_id ORDER BY r.vtxo_id) AS vtxo_ids, min(v.expiry) AS expiry_height
FROM lightning_htlc_subscription s JOIN arkoor_receive_output r ON r.subscription_id = s.id
JOIN vtxo v ON v.vtxo_id = r.vtxo_id
GROUP BY s.payment_hash, s.claim_pubkey, s.receiver_mailbox_id
HAVING bool_and(r.delivered_height IS NOT NULL) AND min(v.server_pubkey) = max(v.server_pubkey);
