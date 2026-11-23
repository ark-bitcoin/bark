-- Preserve evidence of an outstanding direct invoice payment until the old
-- server has observed its mailbox delivery. The earlier migration checksums
-- remain valid for databases already running either released version.
DO $$
BEGIN
	IF EXISTS (SELECT 1 FROM arkoor_receive_output WHERE delivered_height IS NULL) THEN
		RAISE EXCEPTION 'undelivered invoice outputs remain; finish or reconcile them on the previous server before upgrading';
	END IF;
END
$$;

DROP TABLE arkoor_receive_output;
ALTER TABLE lightning_htlc_subscription DROP COLUMN arkoor_input_ids;
