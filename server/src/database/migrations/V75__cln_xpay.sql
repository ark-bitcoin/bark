--
-- cln_xpay: one row per call to CLN's xpay command.
--
-- This is the lightning side of an outgoing payment: the HTLCs we send out
-- over the network. The ark side, the htlc-send vtxos that fund it, is in
-- htlc_vtxo under the same payment hash. lightning_payment_attempt keeps
-- recording the payment flow for telemetry and mailbox routing; this table
-- records the call itself and what came of it.
--
-- The outcome is copied from the attempt when the attempt ends, so it is our
-- verdict on the call and not CLN's. The two can differ: an attempt failed
-- after an empty listpays can still succeed in CLN later, and 'fail' is
-- terminal here. A reader that acts on the outcome needs it from CLN's own
-- record of the call, which the label finds.
--

CREATE TYPE cln_xpay_status AS ENUM (
	'pending',
	'success',
	'fail'
);

CREATE TABLE cln_xpay (
	id                      BIGSERIAL PRIMARY KEY,

	-- the node the xpay command was issued on
	lightning_node_id       BIGINT NOT NULL REFERENCES lightning_node (id),

	-- request parameters (immutable). Only what a reader needs is stored, not
	-- the full xpay request; the invoice itself is the sender's to keep.
	--
	-- Some parameters are not stored as CLN takes them:
	--   * payment_amount_msat is the amount the recipient is to receive: the
	--     invoice amount, or the sender-supplied amount for an invoice
	--     without one. Only the latter is passed to xpay (as amount_msat).
	--   * max_routing_fee_msat is xpay's maxfee: the sender loses at most
	--     payment_amount_msat + max_routing_fee_msat.
	--   * attempt_expiry replaces retry_for (CLN takes relative seconds):
	--     the absolute timestamp after which xpay stops retrying
	--     (created_at + retry_for). Required: it tells a transient failure
	--     from a final one.
	--   * htlc_expiry replaces maxdelay (CLN takes relative blocks): the
	--     absolute blockheight before which our outgoing HTLCs must be
	--     resolved (CLN tip at call time + maxdelay).
	payment_amount_msat     BIGINT NOT NULL,
	max_routing_fee_msat    BIGINT,
	attempt_expiry          TIMESTAMPTZ NOT NULL,
	partial_msat            BIGINT,
	htlc_expiry             INTEGER,
	label                   TEXT,

	-- multiple attempts may share a hash
	payment_hash            TEXT NOT NULL,

	-- the fee quoted to the user at initiation, which is ours to keep. Not a
	-- parameter of the xpay call; the routing fee below is what the call costs.
	user_fee_msat           BIGINT,

	-- raw x-user-agent of the initiating client, NULL when none was sent
	user_agent              TEXT,

	-- outcome (mutable). The proof of payment is not here: it lives in
	-- htlc_settlement, keyed by payment_hash, and is written before an
	-- attempt may end as a success.
	status                  cln_xpay_status NOT NULL DEFAULT 'pending',
	-- routing fee actually paid; set on success. This is the difference
	-- between what the sender put on the wire and payment_amount_msat. It is
	-- normally positive but can be negative when the server subsidized the
	-- payment so the recipient still received the intended amount.
	routing_fee_msat        BIGINT,
	-- CLN error code; set on failure. We don't store the full error data.
	error_code              INTEGER,

	created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- each label is handed to exactly one xpay call; ported rows have none
CREATE UNIQUE INDEX cln_xpay_label_ix ON cln_xpay (label) WHERE label IS NOT NULL;

-- queries by payment_hash return all attempts
CREATE INDEX cln_xpay_payment_hash_ix ON cln_xpay (payment_hash);

-- the janitor of one node reads that node's pending attempts on every tick,
-- and they are the few
CREATE INDEX cln_xpay_pending_ix ON cln_xpay (lightning_node_id, id)
	WHERE status = 'pending';

-- An attempt is never submitted a second time, so a call that did not come
-- back leaves a row the janitor has to conclude from CLN's own record. A
-- second attempt on the same hash started while the first is unconcluded
-- would race it for the one outcome the hash can have. The index refuses
-- that second attempt at the source.
CREATE UNIQUE INDEX cln_xpay_pending_hash_ux ON cln_xpay (payment_hash)
	WHERE status = 'pending';


--
-- Port the lightning_payment_attempt rows that made an xpay call.
--
-- An attempt initiated against a lightning_htlc_subscription was paid inside
-- the ark, and no xpay call was ever made for it: the attempt's
-- lightning_htlc_subscription_id records that decision (V55). Every other
-- attempt went out over lightning and becomes a cln_xpay row.
--
-- Self-payments already finished when V55 backfilled that column have no link
-- and port as cln_xpay rows: wrong as history, but nothing reads a finished
-- row.
--

-- Warn when the data breaks an assumption a reader of cln_xpay will rely
-- on. Nothing reads the table yet, so this does not block the upgrade.
DO $$
DECLARE
	unsettled BIGINT;
BEGIN
	-- The proof of a success is its htlc_settlement row. A succeeded
	-- attempt without one ports as a success the server cannot prove;
	-- htlc_settlement only exists since V35, so old servers may have some.
	SELECT count(*) INTO unsettled
	FROM lightning_payment_attempt lpa
	WHERE lpa.status = 'succeeded' AND NOT EXISTS (
		SELECT 1 FROM htlc_settlement hs
		WHERE hs.payment_hash = lpa.payment_hash
	);

	IF unsettled > 0 THEN
		RAISE WARNING
			'% succeeded lightning payment attempts have no htlc_settlement row', unsettled;
	END IF;
END $$;

-- A still-pending attempt ports as pending, and the janitor concludes it from
-- listpays like any other.
INSERT INTO cln_xpay (
	lightning_node_id, payment_amount_msat, attempt_expiry, htlc_expiry,
	payment_hash, user_fee_msat, user_agent, status, routing_fee_msat,
	created_at, updated_at
)
SELECT
	lpa.lightning_node_id,
	lpa.amount_msat,
	-- The retry window handed to xpay. Attempts from before V67 did not
	-- record it; they ran with the operator's cln_xpay_timeout, which SQL
	-- cannot read, and CLN's own default retry_for of 60 seconds is the
	-- conventional upper bound.
	lpa.created_at + COALESCE(lpa.retry_for_secs, 60) * interval '1 second',
	-- The deadline handed to xpay was derived from the linked htlc-send vtxo
	-- policies, which SQL cannot decode. Attempts predating the vtxo link
	-- table have no links either, so every ported row goes without one.
	NULL,
	lpa.payment_hash,
	lpa.user_fee_sat * 1000,
	lpa.user_agent,
	CASE lpa.status
		WHEN 'requested' THEN 'pending'
		WHEN 'submitted' THEN 'pending'
		WHEN 'succeeded' THEN 'success'
		WHEN 'failed' THEN 'fail'
	END::cln_xpay_status,
	-- The legacy final_amount_msat is the total sent including routing fees,
	-- so the fee is what it exceeds the payment amount by.
	CASE WHEN lpa.status = 'succeeded' THEN lpa.final_amount_msat - lpa.amount_msat END,
	lpa.created_at,
	lpa.updated_at
FROM lightning_payment_attempt lpa
WHERE lpa.lightning_htlc_subscription_id IS NULL;
