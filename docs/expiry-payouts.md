Expiry payouts
==============

An Ark server in expiry payout mode pays the VTXOs of an expired tree to their
owners on-chain. Without expiry payouts, the server takes the bitcoin of a VTXO
that its owner did not refresh or exit before the tree expired.

For every VTXO, the server records an owner mailbox key `M` when it co-signs the
VTXO. When the tree expires, the watchman spends the tree and pays each owner to
`tr(M)`, the BIP-86 Taproot key-path output of `M`, minus a payout fee.


# Enable expiry payouts

Set `expiry_payouts = true` in the captaind configuration before you create the
server database. The mode is fixed when the database is created: a database
created without expiry payouts stays in upstream mode.

Run watchmand against the same database. `expiry_payout_max_fee_rate` in the
watchmand configuration sets the highest feerate of a payout transaction and of
its replacements. The watchman pays the miner fee from the value that the
operator owns in the expired tree. If that is not enough, it adds confirmed
inputs of the watchman wallet.

The watchman pays each root of an expired tree with one transaction. A root is
an on-chain output that funds VTXOs, such as the output of a round or a board,
or an output of the tree that an exit confirmed. A spend that is not resolved
holds the payout of every VTXO under its root, so in a tree that nobody exited
it holds the whole tree. The watchman pays the root when the spend resolves.


# The fee rule

The payout fee of an owner is the higher of 2,000 sats and 1% of the value that
the owner has in the tree. The server charges it once for each owner in each
expired tree, whatever the number of VTXOs of the owner.

If the payout after the fee is below the dust limit, the server pays nothing and
reports the VTXOs as forfeited. The operator keeps that value.

The payout outputs of the owners do not change when the watchman replaces a
payout transaction to raise its feerate.


# The protocol version

A server in expiry payout mode accepts only the Scuttle protocol version,
`PROTOCOL_VERSION_SCUTTLE_EXPIRY_PAYOUT` in `server-rpc/src/pver.rs`. It
refuses other versions with the error for a client that is too old. A server
without expiry payouts uses the upstream protocol versions.

The wallet is in expiry payout mode when it negotiates the Scuttle protocol
version with the server. In that mode, the wallet sends its owner mailbox in
every request that makes a VTXO: board, arkoor, round and Lightning requests.


# The wallet

The wallet derives its mailbox keypair from the seed, at `m/350'/1'`. An app can
supply another mailbox keypair with `WalletSeed::with_mailbox_keypair`, for
example the key of an on-chain wallet of the app. You must supply the same
keypair on every open. The wallet stores the public key when it first connects
to a server in expiry payout mode, and from then on refuses to open with another
mailbox keypair.

Set `Config::require_expiry_payouts` to open the wallet only with a server in
expiry payout mode.

An arkoor address carries a blinded mailbox. The server unblinds it with the
key of the output and records the result as the owner mailbox of the output.
The sender chooses the address, so the address alone does not prove who owns
the mailbox. A wallet credits a received VTXO only when the server reports it
spendable and bound to the mailbox of the wallet. A received VTXO that is not
spendable on the server yet stays locked until it is.

The bitcoin of a payout arrives at `tr(M)`, not in the Ark balance. Watch that
output with an on-chain wallet. `Wallet::payout_script` returns it.


# What the wallet reports

`Wallet::sync` asks the server about the expired VTXOs that the wallet still
holds. For a VTXO with an expiry payout, the wallet marks the VTXO spent and
records the payout state:

- `pending`: the payout transaction is less than six blocks deep.
- `paid`: the payout transaction is at least six blocks deep.
- `forfeited`: the fee is not less than the VTXO amount, so the server pays
  nothing.

`WalletVtxo::expiry_payout_state` holds the state. `Wallet::expiry_payout`
returns the state, the VTXO amount, the fee, the payout amount and the payout
address. The REST API returns the state in the `expiry_payout` field of a VTXO,
and the full payout at `GET /api/v1/wallet/vtxos/{id}/expiry-payout`.

This is what the server reports. Confirm the payout output on-chain before you
count it as received.

A round, offboard or Lightning action that holds a VTXO ends when the server
pays out that VTXO. A server in expiry payout mode does not register an arkoor
output after its expiry. It refunds the arkoor to the sender on-chain instead.


# Ark address route hints

A Lightning invoice can carry the Ark address of the receiver in two route
hints. A payer on the same Ark server then pays the invoice with an arkoor to
that address, without a Lightning payment. This feature does not need expiry
payouts.

Each route hint is one hop over a channel that does not exist. Its short channel
id starts with `ark\x01` for the hint with the public key of the address, or
`ark\x02` for the hint with the blinded mailbox. The last four bytes of both are
the Ark id of the address. Lightning payers find no route through these hints
and pay the invoice as usual.

To enable it:

- Set `ln_receive_ark_address_hints = true` in the captaind configuration.
- Set `lightning_ark_address_hints = true` in the configuration of the
  receiving wallet and of the paying wallet.

The paying wallet asks the server to co-sign the arkoor with
`RequestLightningReceiveArkoorCosign`. The server settles the Lightning receive
when it co-signs, so the invoice cannot be paid again. The payer gets no
preimage as proof of payment.

In expiry payout mode, the server binds the output of that arkoor to the
mailbox of the receiving wallet. The expiry payout of the VTXO goes to the
receiver once the VTXO is registered with the server. The paying wallet
registers it after the co-sign, and the receiving wallet registers it when it
receives it. An output that the payer never registers and never delivers stays
with the payer, and an expiry payout pays it to the payer.

The server reports the receive as settled when it co-signs the arkoor. A client
must treat the invoice as paid only when the wallet holds the VTXOs.
