CHANGELOG
=========

For more elaborate changelogs, refer to our documentation:
https://docs.second.tech/changelog/changelog/

Below is a more concise summary for each version.

# v0.1.0-beta.5

- `all`
  - Change variants of the word "cancel" to the US spelling.
    This effects REST endpoints, function names and RPC types/names.
    [#1415](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1415)
- `ark-lib`
  - add Vtxo::is_fully_signed to check whether a VTXO is fully signed
    (this check is obviously included in the validation procedure)
    [PR 1293](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1293)
  - Added `get_final_amount` to `lightning::Invoice`, allowing an explicit
    user-provided amount for payment, if it is at least the invoice amount
    and at most double, per BOLT 4.
    [#1331](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1331)
  - The notion of arkoor-depth has been removed.
    Clients can now send their vtxos irregardless of their depth
      - the `max_arkoor_depth` has been removed from `ArkInfo`
      - `Vtxo::is_arkoor` is removed
      - `Vtxo::arkoor_depth` is removed
        [#1342](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1342)
  - Change validate_issuance method to take an Offer by reference
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Implement serialization and deserialization for ark::Address
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - make compatible with WASM for the web and ensure compatibility in CI
    ([PR 1363](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1363))
  - Created a new `challenges` module to centralize VTXO ownership challenge types.
    Challenge implementations for round attempts and Lightning receives have been moved
    from `rounds` and `lightning` modules to this new module.
    `VtxoOwnershipChallenge` was renamed to `RoundAttemptChallenge` to better describe
    its usage. A `VtxoStatusChallenge` type was introduced for usage with the upcoming
    VTXO status endpoint to authenticate queries.
    [#1368](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1368)
- `bark`
  - bark will not consider arkoor-depth anymore.
    `Wallet:select_vtxos_to_cover` doesn't require the arkoor_depth argument anymore
    `bark vtxos` and other calls will not return an arkoor_depth anymore
  - Bark's `pay_lightning_invoice` is made non-blocking. It will ask Server to
    initiate payment but won't wait for settlement. To check payment progress,
    `check_lightning_payment` should now be used, optionally with wait=true
    argument. `pay_lightning_offer` and `pay_lightning_address` are also affected
    [1401](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1401)
  - remove support for recovering round VTXOs from past rounds
    ([PR #1417](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1417))
  - Renamed `Wallet::movements` to `Wallet::history`
    Multiple users struggled to find the functionality they needed
    [#1455](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1455)
- `bark-cli`
  - add round command group to `bark` with `progress` and `cancel` commands
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - add `RoundSatus::Canceled` round status to bark-json
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - `lightning pay` command doesn't wait for payment settlement anymore. To do
    so, `--wait` argument must be set.
    [1401](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1401)
  - Add --no-sync options to exit list and exit status commands
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)- Renamed `movements` to history
    Multiple users struggled to find the functionality they needed
    [#1455](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1455)
- `bark-json`
  [PR 1354](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1354)
  - Movements are ordered by creation date followed by ID from newest to oldest
  - `Movement::metadata` is now JSON instead of a string.
  - `MovementTimestamp` now uses `DateTime<chrono::Local>` instead of `DateTime<Utc>`
  - `VtxoState::Locked::movement_id` as a number instead of a string.
  - Implement a strongly typed PaymentMethod to use for MovementDestination
    Allows for easy serialization and deserialization of address/invoice formats
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Rename MovementStatus::Finished to MovementStatus::Successful
    Also use kebab-casing
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Preimage field has been removed from `LightningPayResponse` struct.
    [1401](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1401)
  - PendingRoundInfo's kind field has been replaced by status,
    and its value is now an enum instead of a string.
    [1445](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1445)
- `bark-rest`
  - Implement a typed payment method to use for sent_to/received_on destinations
    Allows for easy serialization and deserialization of address/invoice formats
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Rename MovementStatus::Finished to MovementStatus::Successful
    Also use kebab-casing
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
- `bark-wallet`
  - Add `Wallet::maybe_schedule_maintenance_refresh`
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - Add `Wallet::participate_ongoing_rounds`
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - Rename `Wallet::progress_ongoing_rounds` to `Wallet::progress_pending_rounds`
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - Add `Wallet::cancel_all_pending_rounds` and `Wallet::cancel_pending_round`
    ([PR 1328](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1328))
  - Use the new `get_final_amount` from `ark::lightning::Invoice` to check
    and get the final amount to use for payment
    [#1331](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1331)
    [PR 1354](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1354)
  - Movements are ordered by creation date followed by ID from newest to oldest
  - `MovementTimestamp` now uses `DateTime<chrono::Local>` instead of `DateTime<Utc>`
  - Rename `BarkPersister::get_movement()` to `get_movement_by_id()`
    [PR 1355](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1355)
  - `crate::error::movement` is now `crate::movement::error`
  - `BarkPersister::get_movements` is renamed to `get_all_movements`
  - Make rand module optional
  - Remove _at variants from the MovementManager
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Add [new|finish]_movement_with_update methods to the MovementManager
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Add new_guarded_movement to the MovementManager and stop defaulting on-drop behaviour of the MovementGuard
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Remove status from MovementGuard::finish and add MovementGuard::[cancel|fail] methods instead
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Improve MovementError messages
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Implement a strongly typed PaymentMethod to use for MovementDestination
    Allows for easy serialization and deserialization of address/invoice formats
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Add the payment hash to lightning movement metadata
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Rename MovementStatus::Finished to MovementStatus::Successful
    Also use kebab-case for JSON and OpenAPI enums
    [#1362](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1362)
  - Rework ExitVtxo to remove the VTXO-marking step
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Fix a bad bug with HTLCs that must be exited but never are
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Syncing and progressing in the exit system is split up how it was originally intended
    Syncing is controlled by the library user, it won't happen automatically when calling progress_exits anymore.
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - No longer store the entire VTXO for every exit every time we load the wallet
    Should result in a better memory footprint when the wallet contains or performed unilateral exits.
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Make sure we don't accidentally spend user funds during sync_exits if their transaction falls out of the mempool
    The previous behaviour would have allowed a unilateral exit to go from AwaitingDelta -> Processing which could have
    resulted in funds being spent when new CPFP packages are created.
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
- `server`
  [#1292](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1292)
  - Deprecating `PostArkoorPackageMailbox` and `EmptyArkoorMailbox` gRPC methods of the Ark server.
  - Creation of new gRPC methods `PostVtxosMailbox`, `SubscribeMailbox` and `ReadMailbox` with checkpoint system. Introduced via new proto file `mailbox.proto`.
  - Use the new `get_final_amount` from `ark::lightning::Invoice` to check
    and get the final amount to use for payment
    [#1331](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1331)
  - `captaind` will not look at arkoor-depth anymore.
    It will still tell old-clients a very high arkoor depth to
    ensure backward compatibility.
    [#1342](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1342)
  - `initiate_lightning_payment` doesn't wait for payment settlement anymore and
    now returns an empty response instead of payment status.
    `check_lightning_payment` can be called after payment iniated to check status
    or wait for settlement.
    [1401](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1401)
  - `check_lightning_payment` return type has been simplied. It now returns a
    simple payment status enum, with preimage if payment succeeded
    [1401](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1401)
  - Added `invoice_expiry` config option to set the duration after which a
    generated invoice expires (corresponds to the BOLT 11 `expiry` field).
    Defaults to 48 hours.
    [1419](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1419)
  - Added `receive_htlc_forward_timeout` config option to set the duration the
    server will hold inbound HTLC(s) while waiting for a user to claim a
    lightning receive. After this timeout the server will fail the HTLC(s) back
    to the sender and cancel the hold invoice. Defaults to 30 seconds.
    [1419](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1419)
  - Removed `htlc_subscription_timeout` config option.
    [1419](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1419)
  - The server now cancels pending lightning receive subscriptions and hold
    invoices upon invoice expiry if there is no ongoing inbound payment,
    freeing up resources.
    [1419](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1419)
- `server-rpc`
  - several RPC comamnds have been renamed
    - `start_lightning_payment` to `request_lightning_pay_htlc_cosign`
    - `revoke_lightning_payment` to `request_lightning_pay_htlc_revocation`
    - `finish_lightning_payment` to `initiate_lightning_payment`
      This helps better reflecting the actual flow of a lightning payment
      with the Ark Server
      [#1398](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1398)
- `testing`
  - Avoid unintentional refresh in HTLC exit tests
    The change VTXOs were being refreshed which was messing up the order of movements
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Make await_propagation in exit tests avoid syncing
    Due to latency between mempool.space syncing with bitcoin core, bark might download lower-fee packages until
    mempool.space performs its next sync. This is an issue that will be fixed in a different PR.
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Verify movements when exiting HTLCs forcefully
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)
  - Add tests for different movement subsystems
    [#1414](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1414)


# v0.1.0-beta.4

- `barkwallet`
  - Fixed a bug in which HTLC vtxo's weren't properly marked as spent
	[#1345](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1345)

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
