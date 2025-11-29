Help, my neighbour exited
======================

This is a motivating example for checkpoint transactions.

# The exit of a neighbour shouldn't bring your funds onchain

 As a user of Ark you want predictability.
 If your funds hit the chain you will have unexpected costs. Suddenly, you'll have to pay for an onchain transaction

```
⚓funding  ─> node  ─┬─> leaf ──> vtxo A ─┬─> vtxo B
                                          └─> vtxo A (change)
```

Below is an illustration of Bob doing an exit.
Note that Alice's change VTXO is an output of the same
transaction as Bob's VTXO.

Bob has brought both VTXOs onchain
```
⚓funding  ─> ⚓node  ─┬─> ⚓leaf ──> ⚓vtxo A ─┬─> vtxo B
                                                └─> vtxo A (change)
```
	


