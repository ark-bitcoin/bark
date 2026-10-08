--
-- cln_hold: one row per hold invoice created through the hold plugin.
--
-- This is the lightning side of an incoming payment: the HTLCs the node holds
-- for us until we reveal the preimage. The ark side, the htlc-recv vtxos we
-- grant against them, is in htlc_vtxo under the same payment hash.
-- lightning_htlc_subscription keeps recording the receive flow; this table
-- records what the plugin knows about the invoice.
--
-- The status column mirrors the hold plugin's states exactly; the plugin is
-- queried to determine the current state. The path is one-way: 'unpaid',
-- then 'accepted', then 'paid' or 'cancelled', which are terminal.
--
-- The per-state timestamps are informational only: they record when a
-- state was reached.
--
-- The plugin API takes relative times; we store absolute timestamps and
-- blockheights. A column that does hold a delta says so in its name.
--
-- Rows are not ported from lightning_htlc_subscription here: expires_at and
-- min_final_cltv_delta live inside the bolt11, which SQL cannot decode. The
-- `captaind data backfill-cln-hold` command does that port.
--

CREATE TYPE cln_hold_status AS ENUM (
	-- the invoice exists but the node holds no matching HTLCs
	'unpaid',
	-- the node is holding incoming HTLCs for this payment hash
	'accepted',
	-- we fulfilled the held HTLCs by revealing the preimage
	'paid',
	-- we don't serve this invoice anymore
	'cancelled'
);

CREATE TABLE cln_hold (
	id                      BIGSERIAL PRIMARY KEY,

	-- the node the invoice was created on, and so the one holding the HTLCs
	lightning_node_id       BIGINT NOT NULL REFERENCES lightning_node (id),

	-- immutable invoice data; multiple rows may share a payment_hash
	invoice                 TEXT NOT NULL,
	payment_hash            TEXT NOT NULL,
	requested_amount_msat   BIGINT NOT NULL,
	-- the CLTV delta, in blocks, the payer must leave on the last hop. A delta
	-- and not a height, because it binds relative to whichever block the
	-- payment turns up in.
	min_final_cltv_delta    INTEGER NOT NULL,
	-- absolute invoice expiry
	expires_at              TIMESTAMPTZ NOT NULL,

	-- authoritative current state
	status                  cln_hold_status NOT NULL DEFAULT 'unpaid',

	-- the sum of the HTLCs the node is holding, which is what covers the
	-- htlc-recv vtxos we grant. Set on acceptance and left as it was once
	-- paid or cancelled.
	accepted_amount_msat    BIGINT,

	-- the lowest cltv_expiry across the HTLCs the node is holding, so the
	-- blockheight we must have acted by. An accepted hold is HTLCs, and this is
	-- the deadline on them. Set along with accepted_amount_msat.
	lowest_incoming_htlc_expiry INTEGER,

	-- actual settled sum, the held sum when we saw the invoice accepted;
	-- can exceed requested_amount_msat on overpayment
	paid_amount_msat        BIGINT,

	-- informational: when each state was reached
	created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	accepted_at             TIMESTAMPTZ,
	paid_at                 TIMESTAMPTZ,
	cancelled_at            TIMESTAMPTZ,

	updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	-- an accepted hold is HTLCs, and HTLCs have a sum and a deadline
	CONSTRAINT cln_hold_accepted_htlcs_ck CHECK (
		status <> 'accepted'
		OR (accepted_amount_msat IS NOT NULL AND lowest_incoming_htlc_expiry IS NOT NULL)
	)
);

-- queries by payment_hash return all invoices on the hash
CREATE INDEX cln_hold_payment_hash_ix ON cln_hold (payment_hash);

-- the hold process of one node reads that node's open invoices, and they
-- are the few
CREATE INDEX cln_hold_open_ix ON cln_hold (lightning_node_id, id)
	WHERE status IN ('unpaid', 'accepted');
