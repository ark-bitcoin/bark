-- The bitcoin_transaction table was the TxIndex's raw-tx store. With
-- the TxIndex gone and the TxNursery keeping its raw txs in nursery_tx,
-- nothing reads it anymore. Tree funding txs were always persisted in
-- virtual_transaction as well, so no data of value is lost.

DROP TABLE bitcoin_transaction;
