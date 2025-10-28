
Ark Addresses
=============

Transactions within an Ark are called Arkoor transactions. Addressing for Arkoor
transactions is done using Ark addresses.

They are formatted with the bech32m encoding, just like bitcoin addresses, but
start with `ark1` or `tark1` for mainnet and test networks respectively.

Because other Ark implementations use similar addresses, we have a short formal
specification of the address format in a universal repository with cross-Ark
specifications: [BOAT-001](https://github.com/ark-protocol/boats/blob/master/boat-0001.md).

The address encodes three different things:

- an Ark server identifier
- the VTXO policy to be used for sending
- different VTXO delivery methods that can be used to deliver the Arkoor VTXO to the recipient

We'll go into a bit more detail for each of these.


# Ark server identifier

Ark servers are identified by their main public key, which we call the "server
pubkey". It is a fixed public key that is used for all
interactions with the server and should be relatively fixed in time.

In the address, we encode a 4-byte hash of the server public key. This way, when
you receive an address, you can easily see whether the person you are trying to
send money to is on the same Ark as you are.


# Policy

The main thing that you need to communicate to someone that wants to send money
to your is the VTXO policy where you want to receive money. The main one being
used right now it the `Pubkey` policy, which encodes the user's public key.

In the future, however, different policies could be supported such as multi-sig
or even more generalized miniscript-based policies.


# VTXO Delivery

After the server has cosigned an Arkoor transcation for you, you need to
delivery it to the recipient. In the bitcoin on-chain world, you would use the
mempool for that, but in Ark the transactions happen off-chain and we have no
mempool.

By default, the server can act as a message-passer that can inform users when
they have new money being sent to them. However, you might not want to rely on
the server to perform this function honestly. The address format allows users to
provide multiple ways by which they can receive their VTXOs.


## Built-in per-VTXO mailbox

The very simplest way to do this is for the server to keep the VTXO and for the
recipient to ask the server if it has any VTXOs for any of his VTXO public keys.
The server knows all the VTXOs so it can answer this question easily.

## Ark server Unified Mailbox

To optimize the process of asking the server for your VTXOs, we also support a
Unified Mailbox where all your VTXOs can be found together. This avoids you
having to constantly ask the server if you have any new VTXOs for any of your
possibly hundreds of public keys. When using the Unified Mailbox, the server can
notify you when anything enters the mailbox without you having to query.

More on the Unified Mailbox in [docs/mailbox.md].
