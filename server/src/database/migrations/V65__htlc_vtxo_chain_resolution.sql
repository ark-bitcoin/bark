--
-- We track resolution separately for onchain and offchain.
--
-- There is an onchain resolution if we see the htlc was spent onchain using
-- the fulfilment or revocation path.
--
-- The offchain resolution is set by the server when an HTLC is revoked or
-- fulfilled using arkoor.
--
ALTER TABLE htlc_vtxo RENAME COLUMN resolution TO offchain_resolution;

ALTER TABLE htlc_vtxo
	ADD COLUMN chain_resolution htlc_resolution,
	ADD COLUMN chain_resolution_height INTEGER,
	ADD CONSTRAINT htlc_vtxo_chain_resolution_ck
		CHECK ((chain_resolution IS NULL) = (chain_resolution_height IS NULL));

--
-- The moment an htlc vtxo came into existence.
--
-- A payment is only visible in cln_xpay or in the htlc-recv vtxos once it is
-- under way. Until then the freshly written htlc-send rows are the only sign
-- that a sender started one, and that is what this timestamp is read for.
--
ALTER TABLE htlc_vtxo ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();
