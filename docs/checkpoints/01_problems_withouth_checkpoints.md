Partial exit attack
======================

This is a motivating example for checkpoint transactions.
I will show an example where Alice does a malicious exit
to try and steal servers funds.

In this attack Alice will perform a partial exit attack and try
to steal server funds. For this attack, Alice needs a single VTXO and she will
1. construct a tree of out-of-round transactions
2. refresh all her vtxos in a round
3. perform a partial exit
At the end of the attack the server has to broadcast the forfeits.
However, we will show that the server cannot economically do this.


# Construct the tree
Let's dive a little bit deeper. Let's assume alice has a VTXO.

```
⚓funding  ─> node  ─┬─> leaf ──> vtxo A
```

The little anchor `⚓` indicates that the funding transaction
is confirmed onchain. All other transactions aren't confirmed 
on chain. You can see this because they don't have an `⚓` (yet).

Assume Alice VTXO has a value of 1 BTC. She will spend her VTXO out-of-round
into a new transaction which has 4 outputs. For each output she will do it again and again.
This will result in a tree of arkoor transactions as illustrated below.

```
⚓funding  ─> node  ─┬─> leaf ──> vtxo A ─┬─> vtxo A ─┬─> vtxo A ─┬─> vtxo A ─┬─> vtxo A'
                                                     │           │           ├─> vtxo A
                                                     │           │           ├─> vtxo A
                                                     │           │           └─> vtxo A
                                                     │           |
                                                     │           ├─> vtxo A ─┬─> vtxo A
                                                     │           │           ├─> vtxo A
                                                     │           │           ├─> vtxo A
                                                     │           │           └─> vtxo A
                                                     │           |
```

Obviously, we didn't draw the entire tree because it becomes somewhat long. 
If Alice repeats this process 5 times she will have `4*4*4*4*4=1024` vtxos.

# Participating in a round

Alice will refresh her 1024 vtxos and get a single vtxo in return.

# Alice will perform a malicious partial exit

Alice will perform a malicious partial exit.
She will only bring the VTXO which she had originally onchain.

```
⚓funding  ─> ⚓node  ─┬─> ⚓leaf ──> ⚓vtxo A ─┬─> vtxo A ─┬─> vtxo A ─┬─> vtxo A ─┬─> vtxo A -> forfeit
                                                        │           │           ├─> vtxo A -> forfeit
                                                        │           │           ├─> vtxo A -> forfeit
                                                        │           │           └─> vtxo A -> forfeit
                                                        │           |
                                                        │           ├─> vtxo A ─┬─> vtxo A -> forfeit
                                                        │           │           ├─> vtxo A -> forfeit
                                                        │           │           ├─> vtxo A -> forfeit
                                                        │           │           └─> vtxo A -> forfeit
                                                        │           |
```

The server now has to respond. Alice can claim the funds of her onchain vtxo after `exit_delta` amount of blocks.
However, note that all funds in the VTXO have been forfeited. The server faces an expensive decision.

Will the server
- publish the full tree (more than 1000 transactions) and pay onchain costs
- lose funds to Alice

 Notice, that Alice can make this attack exponentially more effective by splitting the tree one level more.

 
