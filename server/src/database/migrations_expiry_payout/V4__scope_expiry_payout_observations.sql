-- Read only the indexed inputs and attempts of the requested payout.
CREATE FUNCTION expiry_payout_observed(payout_id BIGINT)
RETURNS TABLE (confirmed BOOLEAN, conflicted BOOLEAN, confirmed_txid TEXT, height BIGINT)
LANGUAGE SQL STABLE
BEGIN ATOMIC
	SELECT COUNT(i.vtxo_id) > 0
			AND BOOL_AND(v.onchain_spent_txid IS NOT NULL AND b.height IS NOT NULL AND p.txid IS NOT NULL)
			AND COUNT(DISTINCT v.onchain_spent_txid) = 1,
		BOOL_OR(v.onchain_spent_txid IS NOT NULL AND p.txid IS NULL)
			OR COUNT(DISTINCT v.onchain_spent_txid) > 1,
		MIN(v.onchain_spent_txid),
		MIN(b.height)
	FROM expiry_payout_input i
	LEFT JOIN vtxo v ON v.vtxo_id = i.vtxo_id
	LEFT JOIN watchmand_block b ON b.height = v.onchain_spent_height
	LEFT JOIN expiry_payout_attempt p ON p.expiry_payout_id = i.expiry_payout_id AND p.txid = v.onchain_spent_txid
	WHERE i.expiry_payout_id = payout_id;
END;

CREATE OR REPLACE VIEW v_expiry_payout_state AS
SELECT a.id, a.expiry_height,
	CASE WHEN o.confirmed THEN o.confirmed_txid ELSE latest.txid END AS payout_txid,
	CASE WHEN o.confirmed THEN winner.signed_tx ELSE latest.signed_tx END AS payout_tx,
	a.broadcast_at,
	CASE WHEN o.confirmed THEN 'confirmed'
		WHEN o.conflicted OR EXISTS (
			SELECT 1 FROM expiry_payout_vtxo c
			JOIN expiry_payout_vtxo paid ON paid.vtxo_id = c.vtxo_id AND paid.expiry_payout_id <> a.id
			CROSS JOIN LATERAL expiry_payout_observed(paid.expiry_payout_id) prior
			WHERE c.expiry_payout_id = a.id AND prior.confirmed)
		THEN 'conflicted' ELSE 'pending' END AS status,
	CASE WHEN o.confirmed THEN o.height END AS confirmed_height
FROM expiry_payout a
CROSS JOIN LATERAL expiry_payout_observed(a.id) o
LEFT JOIN expiry_payout_attempt winner
	ON winner.expiry_payout_id = a.id AND winner.txid = o.confirmed_txid
LEFT JOIN LATERAL (SELECT p.txid, p.signed_tx FROM expiry_payout_attempt p
	WHERE p.expiry_payout_id = a.id ORDER BY p.fee_sat DESC LIMIT 1) latest ON TRUE;
