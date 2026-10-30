--
-- board_exit: the one exit tx a board funding output may be cosigned and
-- registered with. Keyed on the funding script too, so a request with
-- someone else's outpoint but its own keys can't claim their output.
--

CREATE TABLE board_exit (
	funding_outpoint  TEXT NOT NULL,
	funding_spk       BYTEA NOT NULL,
	exit_txid         TEXT NOT NULL,
	created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	PRIMARY KEY (funding_outpoint, funding_spk)
);
