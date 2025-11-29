# Checkpoint transactions

When making an arkoor-transaction we will add an extra checkpoint transaction.

```
(original vtxo)                              (Checkpoint)                      (bobs new VTXO)
+-------+--------------------+              +-------------------------+       +------+----------------------+
| 2 BTC | A + S or A + delta |   ---------> | 1 BTC | A + S or S + T  | ---> | 1 BTC | B + S or S + delta   |
+----------------------------+              +-------------------------+       +------+----------------------+
                                            | 1 BTC | A + S or S + T  | -┐    (Alices new VTXO)
                                            +-------------------------+  │  +-------------------------------+
                                                                         └->| 1 BTC | A + S or S + delta    |
                                                                            +-------+-----------------------+
```

Note, that the checkpoint transaction has two outputs.
This is intentional. If Bob would exit only the checkpoint transaction and his exit transaction goes onchain, Alice's VTXOs would be unaffected. Alice can still use her change VTXO and the server can sweep the checkpoint after expiry.

Also, note that if Alice would construct a tree of transactions the server can always respond cheaply.
The server just has to broadcast a single exit transaction.

If the exit transaction is huge this would still be expensive.
Therefore, the server should limit the number of outputs in the checkpoint transaction.
