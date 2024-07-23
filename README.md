rust-ark
========

An implementation of the Ark second-layer payment protocol for Bitcoin.

This repository comprises an ASP server, `aspd`, a client wallet, `bark`, and
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

Then we create and configure an ark-server using the `aspd`-command. Our ark-server
will run on `regtest` and use the `bitcoin`-node we've started a few lines before.

```
aspd create \
    --network regtest \
    --datadir ./test/arkdatadir \
    --bitcoind-url $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE
```

The server can be started using 

```
aspd start --datadir ./test/arkdatadir
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
bark --datadir ./test/bark create \
    --regtest \
    --asp http://localhost:3535 \
    --bitcoind $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE

bark --datadir ./test/bark2 create \
    --regtest \
    --asp http://localhost:3535 \
    --bitcoind $BITCOIND_URL \
    --bitcoind-cookie $BITCOIND_COOKIE
```

These will create individual wallets and print an on-chain address you can use
to **fund them the same way as you did for the ASP above**. Note that clients
can receive off-chain Ark transactions without having any on-chain balance, but
a little bit of on-chain money is needed to perform unilateral exits.

You can find the wallet using
```
BARK1_ADDR=$(bark --datadir ./test/bark1 get-address)
bcli generatetoaddress 1 $BARK1_ADDR
bcli generatetoaddress 100 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

To use the onchain wallets, there are a few commands available:

```
BARK2_ADDR=$(bark --datadir ./test/bark2 get-address)
bark --datadir ./test/bark1 send-onchain $BARK2_ADDR "0.1 btc"
bark --datadir ./test/bark2 balance
```

Once we have money, we can onboard into the Ark, afterwards the balance will
also show an off-chain element.

```
bark --datadir ./test/bark1 onboard "1 btc"
bark --datadir ./test/bark1 balance
```

Remember that all txs will just be in the mempool if you don't generate blocks
once a while...
 
```
bcli generatetoaddress 1 mtDDKi5mDjZqGzmbnfUnVQ8ZhCPMPVsApj
```

Then, let's send some money off-chain:

```
## Should be empty..
BARK2_PK=$(bark --datadir ./test/bark2 get-vtxo-pubkey)
# For now every client has just a single pubkey.
echo "${BARK2_PK}"
bark --datadir ./test/bark1 send-round ${BARK2_PK} "0.1 btc"
bark --datadir ./test/bark2 balance
```

You will notice that there is a slight delay when sending, this is because the
client needs to wait for the start of the next round and currently no
out-of-round payments are supported. The round interval can be changed in the
`aspd` configuration.
