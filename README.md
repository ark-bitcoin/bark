rust-ark
========

An implementation of the Ark second-layer payment protocol for Bitcoin.

This repository comprises an ASP server, `arkd`, a client wallet, `noah`, and
a library that contains all the primitives used for these implementations.

# Demo

The `ark_demo.sh` script creates a nice environment to play with `ark`.

```
source ark_demo.sh
```

First you have to setup a regtest bicoind node. If you already have a `regtest`-node
you can use that one. You just have to ensure that `txindex` is enabled. However, the
tutorial is easier to follow if you spin up a new regtest node.

```
bd --daemon
```

You can always use `type -a bd` to see what the alias does. In this case it will tell 
you that `bd` is an alias for 
`bitcoind -regtest -datadir=/ark/test/bitcoindatadir -server -txdindex`.

You can use the `bitcoin-cli` which is aliased to `bcli` to interact with the node.     

```
bcli getnetworkinfo
```

Then we create and configure an ark-server using the `arkd`-command. Our ark-server
will run on `regtest` and use the `bitcoin`-node we've started a few lines before.

```
arkd create \
    --network regtest \
    --datadir ./test/arkdatadir \
    --bitcoind-url $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE
```

The server can be started using 

```
arkd start --datadir ./test/arkdatadir
```

The server will start working immediately but requires some funds to work properly. 
You can find an the onchain address in the logs and send some funds to it.

```
bcli generatetoaddress 1 <asp-addr>
```

The funds are only useable after we generate 100 extra blocks.

```
bcli generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Next, you can start some clients. To create a client, use the following command:

```
noah --datadir ./test/noah1 create \
    --regtest \
    --asp http://localhost:35035 \
    --bitcoind $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE

noah --datadir ./test/noah2 create \
    --regtest \
    --asp http://localhost:35035 \
    --bitcoind $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE
```

These will create individual wallets and print an on-chain address you can use
to **fund them the same way as you did for the ASP above**. Note that clients
can receive off-chain Ark transactions without having any on-chain balance, but
a little bit of on-chain money is needed to perform unilateral exits.

You can find the wallet using
```
NOAH1_ADDR=$(noah --datadir ./test/noah1 get-address)
bcli generatetoaddress 1 $NOAH1_ADDR
bcli generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

To use the onchain wallets, there are a few commands available:

```
NOAH2_ADDR=$(noah --datadir ./test/noah2 get-address)
noah --datadir ./test/noah1 send-onchain $NOAH2_ADDR "0.1 btc"
noah --datadir ./test/noah2 balance
```

Once we have money, we can onboard into the Ark, afterwards the balance will
also show an off-chain element.

```
noah --datadir ./test/noah1 onboard "1 btc"
noah --datadir ./test/noah1 balance
```

Remember that all txs will just be in the mempool if you don't generate blocks
once a while...
 
```
bcli generatetoaddress 1 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Then, let's send some money off-chain:

```
## Should be empty..
NOAH2_PK=$(noah --datadir ./test/noah2 get-vtxo-pubkey)
# For now every client has just a single pubkey.
echo "${NOAH2_PK}"
noah --datadir ./test/noah1 send-round ${NOAH2_PK} "0.1 btc"
noah --datadir ./test/noah2 balance
```

You will notice that there is a slight delay when sending, this is because the
client needs to wait for the start of the next round and currently no
out-of-round payments are supported. The round interval can be changed in the
`arkd` configuration.
