DROP INDEX round_tx_id_ix;
CREATE UNIQUE INDEX round_funding_tx_id_uix ON round (funding_txid) INCLUDE (swept_at);
CREATE UNIQUE INDEX round_seq_uix ON round (seq);

CREATE UNIQUE INDEX vtxo_vtxo_id_uix ON vtxo (vtxo_id);

DROP INDEX sweep_tx_id_pending_ix;
CREATE UNIQUE INDEX sweep_txid_pending_uix ON sweep (txid) INCLUDE (abandoned_at, confirmed_at);

CREATE UNIQUE INDEX arkoor_mailbox_vtxo_id_uix ON arkoor_mailbox (vtxo_id);
