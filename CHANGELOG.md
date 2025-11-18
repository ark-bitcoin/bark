CHANGELOG
=========

For more elaborate changelogs, refer to our documentation:
https://docs.second.tech/changelog/changelog/

Below is a more concise summary for each version.


# v0.1.0-beta.3

- `ark-lib`
  - added `offboard_feerate` field to `ArkInfo`.
    The offboard feerate is now fixed and no longer specified JIT for each
  round.
    [#1070](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1070)
  - Removed the `RoundEvent::Start` variant.
    [#1070](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1070)
  - A new field `ln_receive_anti_dos_required` has been added to the `ArkInfo` struct, indicating
    whether the Ark server requires clients to either provide a VTXO ownership proof, or a Lightning
    receive token when preparing a Lightning claim as an anti-denial-of-service measure.
    [#1183](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1183)

- `bark-wallet`
  - A full rewrite occured on how state is managed internally.
    - increased stability
    - can sign up to a round and make round progress asynchronously
    - input VTXOs are locked at signup to the round
    - output VTXOs are made available as soon as we have signed funding tx
    - round state is only fully cleared when the funding tx deeply confirms or all failed rounds
  	are unlikely to ever confirm
    - round state is only fully cleared when the funding tx deeply confirms or all failed rounds
	  are unlikely to ever confirm
      [#1070](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1070)
  - rename some lightning methods to be more consistent
    [#1279](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1279)
    - `send_lnaddr` -> `pay_lightning_address`
    - `pay_offer` -> `pay_lightning_offer`
    - `send_lightning_payment` -> `pay_lightning_invoice`
    - `check_and_claim_all_open_ln_receives` -> `try_claim_all_lightning_receives`
    - `check_and_claim_ln_receive` -> `try_claim_lightning_receive`
  - store lightning receive payment hash and preimage as hexes instead
    of strings. This also fixes a bug preventing any lightning receive
    deletion.
    [#1285](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1285)
  - remove `preimage_revealed_at is NULL` filter when fetching pending
    lightning receive. This was preventing us from claiming again after
    first claim if anything bad happened
    [#1285](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1285)
  - return earlier in `check_lightning_receive` when we already got our
    htlc VTXOs. This saves us one useless gRPC call to the server
    [#1285](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1285)
  - big refactor of the movements API and related types
    [#1275](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1275)
  - add experimental `Daemon` to run background tasks
    [#1297](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1297)

- `bark-cli`
  - Refresh, offboard and all other commands that participate in
    a round are now returning `RoundStatus`.
    Previously, they only returned the `funding_txid`.
    [#1070](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1070)
  - The `bark ln claim` command now accepts an optional `--token` argument, allowing you to
    provide a Lightning receive token to receive via Lightning even if you do not have any
    existing VTXOs in the Ark. This acts as an anti-denial-of-service measure for the Ark
    server which can be optionally enforced by the server. Tokens will be distributed by
    integrators or directly by the Ark operator.
    [#1183](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1183)
  - no longer all bark config variables are required, default values will be filled for missing
    values
    [PR 1254](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1254)
  - `bark create` command now works if an existing config.toml file is in place in the datadir
    [PR 1254](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1254)
  - remove some config options from `bark create` command, use config file instead
    [PR 1254](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1254)
  - add experimental `barkd` daemon with REST HTTP server and background
    process

- `bark-rest`
  - Add new endpoints in bark-rest
    - `GET /bitcoin/tip` : fetch current bitcoin tip on barkd's bitcoin
      node
    - `GET /wallet/connect` : fetch ark server connection status
    - `GET /ping` : ping barkd
      [#1291](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1291)

- `bark-server`
  - `SubscribeRoundEvents` gRPC no longer opens with the last happened event,
    use `LastRoundEvent` if you want the last event
    [#1070](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1070)
  - A new configuration variable, `ln_receive_anti_dos_required`, was added which indicates whether
    the server requires clients to either provide a VTXO ownership proof, or a Lightning receive
    token when preparing a Lightning claim.
    [#1183](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1183)


# v0.1.0-beta.1

First "beta" version, with an aim to somewhat stabilize the bark-wallet API.

For changes since the latest alpha version, see the detailed changelog in the
docs.
