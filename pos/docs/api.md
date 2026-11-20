# posd HTTP API

posd is the point-of-sale service. It serves the terminal PWA, the owner API
and LNURL. All bodies are JSON. Enum values use kebab-case. Amounts in sats
are integers. Fiat amounts are decimal strings in the store currency, for
example `"12.50"`. Times are RFC 3339 strings in UTC.

Errors return a non-2xx status with `{"error": "<message>"}`:

| Status | Meaning |
|---|---|
| 400 | The request is not valid |
| 401 | The token is missing, not valid, or revoked |
| 404 | The resource does not exist for this caller |
| 409 | The request conflicts with the current state |
| 502 | An upstream service (Ark server, barkd, price feed) failed |

## Payment rails

| Rail | `paid_rail` | Payer | How posd knows it is paid |
|---|---|---|---|
| Lightning | `lightning` | Any Lightning wallet, or a scuttle wallet without long-lived VTXOs | barkd delivered the claim to the owner's mailbox |
| Ark | `ark` | A scuttle wallet on the same Ark server | the Ark server certified delivery of the arkoor |
| On-chain | `onchain` | Any bitcoin wallet | 1 confirmation |

The QR code is one BIP 321 URI:

```text
bitcoin:<onchain address>?amount=<btc>&lightning=<bolt11>&ark-lightning=<bolt11>
```

- `lightning` is the forwarding invoice. Every Lightning wallet can pay it.
- `ark-lightning` is the hinted invoice. Only a scuttle wallet reads it. A
  Lightning wallet cannot pay it, so it is never the `lightning` value.
- The address and `amount` are left out when the sale amount is below the
  store's `onchain_min_sat`. The URI is then `bitcoin:?lightning=…`.

## Types

### Sale

```json
{
  "id": "4f1c9a2e-…",
  "created_at": "2026-11-20T15:04:05Z",
  "expires_at": "2026-11-20T15:14:05Z",
  "state": "open",
  "amount_sat": 35000,
  "fiat_amount": "12.50",
  "currency": "CRC",
  "btc_price": "62500000.00",
  "memo": "2 coffees",
  "payment_request": "bitcoin:bc1p…?amount=0.00035&lightning=lnbc…&ark-lightning=lnbc…",
  "lightning_invoice": "lnbc…",
  "ark_invoice": "lnbc…",
  "onchain_address": "bc1p…",
  "paid_at": null,
  "paid_rail": null,
  "received_sat": 0,
  "device_name": "Front till"
}
```

- `state` is `open`, `in-progress`, `paid`, `expired` or `canceled`.
  - `in-progress` means an on-chain payment is in the mempool. The sale stays
    `in-progress` past `expires_at` until the payment confirms.
  - `paid` is final. `received_sat` can be higher than `amount_sat` when the
    payer overpaid or paid more than one rail.
- `paid_rail` is `lightning`, `ark`, `onchain` or `null`.
- `onchain_address` is `null` below the on-chain minimum.
- `fiat_amount`, `currency` and `btc_price` are `null` when the sale was keyed
  in sats.
- `device_name` is `null` for a Lightning address payment.

### Store

```json
{
  "name": "Café Uvita",
  "currency": "CRC",
  "onchain_min_sat": 50000,
  "lightning_address": "cafe@pay.example.com"
}
```

`lightning_address` is `null` when the store has no name.

## Terminal

A terminal sends `Authorization: Bearer <device token>`.

### Pairing

- `GET /pair/<code>` serves the PWA. The page links the manifest
  `/pair/<code>/manifest.webmanifest`, whose `start_url` is `/pair/<code>`, so
  the installed app opens with the code.
- `POST /api/v1/pair` with `{"code": "<code>", "device_name": "Front till"}`
  returns `{"token": "<device token>", "store": Store}`. A code works once.
  `404` means the code is unknown, used or expired.

### Endpoints

| Method and path | Body | Returns |
|---|---|---|
| `GET /api/v1/terminal` | | `{"store": Store, "device_name": "Front till"}` |
| `GET /api/v1/rate` | | `{"currency": "CRC", "btc_price": "62500000.00", "fetched_at": "…"}` |
| `POST /api/v1/sales` | `{"fiat_amount": "12.50", "memo": "…"}` or `{"amount_sat": 35000, "memo": "…"}` | `Sale` |
| `GET /api/v1/sales/<id>` | | `Sale` |
| `GET /api/v1/sales/<id>?wait=<state>` | | `Sale`, returned when the state is not `<state>` or after 25 s |
| `POST /api/v1/sales/<id>/cancel` | | `Sale`; `409` unless the sale is `open` |
| `GET /api/v1/sales?before=<id>&limit=<n>` | | `{"sales": [Sale]}`, newest first, at most 100 |
| `GET /api/v1/sales.csv?from=<date>&to=<date>` | | CSV, one row per sale |

`memo` is optional and at most 200 characters.

`from` and `to` are dates (`2026-11-20`, in UTC) or RFC 3339 times. A date as
`to` includes that whole day.

The CSV columns are: `id, created_at, paid_at, state, paid_rail, amount_sat,
received_sat, fiat_amount, currency, btc_price, memo, device_name`.

## Owner

The owner is the Ark address that registered the store. The owner's wallet
signs with its Ark key, using bark's message signing (`bark/message` tag,
BIP 340 Schnorr over SHA-256).

### Registration

`POST /api/v1/stores`, with no token:

```json
{
  "registration": {
    "name": "Café Uvita",
    "ark_address": "ark1…",
    "mailbox_id": "02…",
    "onchain_descriptor": "tr([fingerprint/86'/0'/1']xpub…/0/*)",
    "currency": "CRC",
    "timestamp": 1795190400
  },
  "signature": "<hex>"
}
```

The signed message is these lines, joined by `\n`, with no trailing newline:

```text
scuttle-pos registration v1
name:<name>
ark_address:<ark_address>
mailbox_id:<mailbox_id>
onchain_descriptor:<onchain_descriptor>
currency:<currency>
timestamp:<timestamp>
```

posd refuses the registration in these cases:
- The signature does not verify for `ark_address`.
- The timestamp is more than 10 minutes away from its clock.
- The address is not for its Ark server.
- `mailbox_id` does not match the blinded mailbox in the address.
- The descriptor is not a public, ranged descriptor.

A second registration for the same address returns `409`.

The response is `{"store": Store}`.

### Login

1. `POST /api/v1/owner/challenge` with `{"ark_address": "ark1…"}` returns
   `{"challenge": "<text>"}`. The challenge expires after 5 minutes.
2. `POST /api/v1/owner/login` with `{"ark_address": "ark1…", "challenge":
   "<text>", "signature": "<hex>"}` returns `{"token": "<owner token>",
   "expires_at": "…"}`. The token lasts 24 hours.

### Endpoints

The owner sends `Authorization: Bearer <owner token>`.

| Method and path | Body | Returns |
|---|---|---|
| `GET /api/v1/owner/store` | | `Store` |
| `PATCH /api/v1/owner/store` | any of `name`, `currency`, `onchain_min_sat`, `lightning_address_name` | `Store` |
| `POST /api/v1/owner/invites` | | `{"code": "…", "url": "https://…/pair/<code>", "expires_at": "…"}`; valid for 24 hours |
| `GET /api/v1/owner/devices` | | `{"devices": [{"id": 1, "name": "…", "created_at": "…", "revoked_at": null}]}` |
| `DELETE /api/v1/owner/devices/<id>` | | `204` |
| `GET /api/v1/owner/sales?before=<id>&limit=<n>` | | `{"sales": [Sale]}` |
| `GET /api/v1/owner/sales.csv?from=<date>&to=<date>` | | CSV |

## LNURL

A store with a `lightning_address_name` answers LUD-06 and LUD-16:

- `GET /.well-known/lnurlp/<name>` returns the pay request. `minSendable` is
  1,000 msat and `maxSendable` is set in the posd config.
- `GET /api/v1/lnurlp/<name>/callback?amount=<msat>` creates a sale with no
  device and returns `{"pr": "<forwarding invoice>", "routes": []}`.
