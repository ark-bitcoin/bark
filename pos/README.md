# posd

posd is the scuttle point-of-sale service. Staff pair a phone or tablet with a
store, install the terminal as a web app, key in an amount and show one QR
code. Every payment goes to the store owner's wallet, which does not need to
be online. posd holds no funds, and a terminal cannot send.

| Rail | The payer uses | Paid when |
|---|---|---|
| Lightning | Any Lightning wallet | barkd delivers the claim to the owner's mailbox |
| Ark | A scuttle wallet on the same Ark server, with long-lived VTXOs | the Ark server certifies delivery (`v_arkoor_receive_delivery`) |
| On-chain | Any bitcoin wallet, at or above the store minimum | 1 confirmation (bitcoind or Esplora); "in progress" before that |

The API is in [docs/api.md](docs/api.md).

## What posd needs

- The Ark server in expiry payout mode, with `ln_receive_ark_address_hints =
  true`.
- A read-only role on the Ark server's database with `SELECT` on
  `v_arkoor_receive_delivery`. See `docs/expiry-payouts.md` in the repository
  root.
- A private barkd. It issues the forwarding invoices and claims them to the
  owner's Ark address. It needs no funds.
- A chain source for on-chain sales: a bitcoind, where posd creates a
  watch-only wallet, or an Esplora API.
- A Postgres database for posd.

## Build and run

```sh
just build-pos-web           # builds pos/web/dist, which posd embeds
cargo build --release -p scuttle-pos
posd --config posd.toml start
```

With nix, `nix build .#scuttle-pos` builds both.

`posd.default.toml` documents every setting.

## Owner setup

The owner's wallet registers the store once. It signs the registration
message (`pos/src/registration.rs`, also in `docs/api.md`) with bark's
ordinary message signing (`Wallet::sign_message`, or `POST
/api/v1/message/sign` on barkd). No wallet code is specific to the point of
sale. The registration carries:
- an Ark address and the wallet's mailbox;
- the public descriptor of the on-chain account that the host app keeps;
- the store currency.

The wallet signs it with the key of the Ark address. The owner then logs in
by signing a challenge, creates pairing links for the terminals, and can
revoke a terminal at any time.

## Tests

```sh
just int-pos      # end-to-end tests; posd runs inside the test process
cargo test -p scuttle-pos
cd pos/web && npm test && npm run check
```

## Known limits

- **Lightning address:** the Ark server cannot put a description hash in an
  invoice. Wallets that enforce the LUD-06 metadata hash refuse Lightning
  address invoices from posd.
- **Fees:** the forwarding invoice carries the Ark server's Lightning receive
  fee, which is not charged on the Ark rail. Set the receive fee to zero to
  give the owner the full amount on every rail.
