CHANGELOG
=========

For more high-level changelogs, refer to our documentation:
https://docs.second.tech/changelog/changelog/

Below is a more detailed summary for each version.

# v0.4.0

- `ark-lib`
  - Allow offboard tx validation without full vtxos
    `OffboardForfeitContext::new` and `validate_offboard_tx` no longer
    require `AsRef<Vtxo<Full>>`; only signing and finishing do, so clients
    can validate a prepared offboard tx from bare wallet vtxos.
    [#2085](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2085)
  - Use destination-specific dust thresholds for offboards
    `fees::validate_and_subtract_fee_min_dust` takes the dust limit of the
    destination script instead of assuming P2TR, and `VTXO_DUST` replaces
    the P2TR dust constant where vtxo amounts are validated.
    [#2085](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2085)
  - Add `Vtxo::check_standard` returning a descriptive `VtxoStandardnessError`
    The new API pinpoints whether the chain has a sub-dust output, a
    non-standard script, or which sibling along the genesis chain is at
    fault. `Vtxo::is_standard` is retained as a thin `bool` wrapper.
    [#2198](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2198)

- `bark`
  - Rework offboards into crash-safe, resumable wallet actions
    Offboards and onchain sends now run through the wallet action executor
    with a persisted checkpoint per step, so an interrupted offboard resumes
    on the next wallet sync instead of being lost. A wallet that loses the
    server's response mid-offboard recovers by adopting the broadcast tx
    from chain, or falls back to preparing a fresh session; if that fresh
    session can no longer succeed (e.g. fee rates moved), the offboard is
    cancelled and its funds are released. A broadcast offboard tx that
    disappears from chain is reported instead of silently retried forever.
    - Pending offboards can be inspected via `Wallet::pending_offboards`
      and are driven by `Wallet::sync_pending_offboards` on every sync
    - How long a vanished offboard tx is re-broadcast before being
      reported lost is configurable via `offboard_lost_tx_grace_period_secs`
      (default one hour)
    - Failed offboards finish their movement as failed with a zero
      effective balance, since no funds actually left the wallet
    - Existing pending offboards are migrated to the new checkpoint format
    - Input vtxos left locked by an offboard that already failed are
      unlocked by a migration, repeating the cleanup bark 0.2.4 did once
    - Fixed `send_onchain` failing whenever the payment produced change
    - **BREAKING:** `BarkPersister` implementations must provide
      `get_wallet_vtxos`; the pending-offboard methods are removed
    [#2085](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2085)
  - replace all the onchain wallet traits with a single one 
    - remove `SignPsbt`, `GetAddress`, `GetBalance`, `GetWalletTx`, `PreparePsbt`, `ChainSync`
  	`GetSpendingTx`, `MakeCpfp`, `Board`, `ExitUnilaterally`, `DaemonizableOnchainWallet`
    - add `OnchainWalletTrait` to replace all of the above
    - add two additional methods: `is_mine`, `register_tx`
    - remove `get_wallet_tx`
    - remove `get_wallet_tx_confirmed_block`
    - remove `get_spending_tx`
    [#2121](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2121)
  - keep the onchain wallet provided in `Wallet::open` inside `Wallet`
    - change the signature of the `WalletOpenArgs::onchain` field
    - `Wallet::board_amount` no longer takes `onchain` arg
    - `Wallet::board_all` no longer takes `onchain` arg
    - `Wallet::start_daemon` no longer takes `onchain` arg
    - removed `Wallet::maintenance_with_onchain`
  	- use `Wallet::sync_exits` to sync exits
    - removed `Wallet::maintenance_with_onchain_delegated`
  	- use `Wallet::sync_exits` to sync exits
    - removed deprecated `Wallet::run_daemon`
    [#2121](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2121)
  - rename `progress_exits_with_bdk` to `progress_exits_with_cpfp`
    - also doesn't take `onchain` arg anymore
    [#2121](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2121)
  - Route lightning receive through the wallet-action driver
    Inbound payments now use the same checkpointed machinery as arkoor sends, so a
    receive resumes across restarts. Settled receives are recorded permanently,
    keeping the preimage available for an HTLC-recv exit.
    [#2148](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2148)
    - **BREAKING:** `Wallet::bolt11_invoice` gains a `token: Option<String>`; the
      claim-time token moved to invoice generation.
    - **BREAKING:** `Wallet::try_claim_lightning_receive` drops its `token` arg.
    - **BREAKING:** `lightning_receive_status` replaced by
      `lightning_receive_state`, returning `LightningReceiveState`.
    - **BREAKING:** removed `bark::persist::models::LightningReceive` (now at
      `bark::actions::lightning::receive::LightningReceive`).
  - Deprecate Ark server access token surfaces
    Access tokens are not enforced by the server in this repo; the receiving
    side ignores the `ark-access-token` header entirely. The token plumbing is
    now marked `#[deprecated]` and will be removed in a future release. Code
    using these surfaces continues to compile, with a deprecation warning to
    flag migration.
    [#2171](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2171)
    - `bark::Config::server_access_token` field
    - `bark_server_rpc::client::ServerConnectionBuilder::access_token()` method
    - `bark_server_rpc::client::ACCESS_TOKEN_HEADER` constant
    - `bark_server_rpc::client::ConnectError::InvalidAccessToken` variant
  - Harden permissions on the wallet database and filestore
    On open, `SqliteClient` checks the database file's permissions and warns if group or other users can access it, suggesting `chmod 600`. The file is not re-chmod'd on every open, so a deliberate permission setup is left intact. The `FileStorageAdaptor` likewise creates its wallet file owner-only (`0o600`) so wallet state is never world-readable.
    [#2194](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2194)
  - Refuse to start a unilateral exit for a non-standard VTXO
    The exit chain is now checked for sub-dust or non-relay-standard outputs
    before any state is persisted, so users don't burn CPFP fees trying to
    exit a VTXO whose transactions would be rejected by the bitcoin relay
    network.
    [#2198](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2198)
  - Sign recovery mailbox posts
    `post_recovery_vtxo_ids` now proves ownership of the recovery mailbox so
    the server can reject posts from anyone else.
    [#2234](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2234)
  - Make boarding crash-safe by driving it as a wallet action
    Boarding now broadcasts, confirms, and registers under the same
    checkpointed `WalletAction` framework as lightning and arkoor sends, so a
    board survives a crash at any point and is re-driven on the next sync,
    including re-broadcasting the funding tx if it drops from the mempool.
    [#2236](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2236)
    - in-flight boards are migrated from the legacy `bark_pending_board` table
      into board action checkpoints; the table is retained (emptied) so a settled
      wallet stays readable by older binaries. The public `board_tx`,
      `board_funding_address`, `board_amount` and `board_all` signatures are
      unchanged.
    - `board_tx` now returns once the board is durably checkpointed; a failed
      initial broadcast no longer errors, since sync retries it. Retrying on error
      would have funded a duplicate board.
  - Let the BIP 321 URI builder run from an async server
    Adds `BarkExtension::ark` and makes `BarkBip321Uri` public.
    [#2242](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2242)
    - **BREAKING:** `BarkBip321UriBuilder::onchain_wallet` now requires `Send`.
  - Error when a maintenance refresh has no usable inputs
    If every VTXO due for a maintenance refresh is rejected by the server as
    unusable, the refresh now returns (and logs) an error instead of silently
    reporting success, so a wallet holding only unspendable inputs surfaces the
    problem rather than quietly no-op'ing forever.
    [#2246](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2246)
  - Add `InputSelection` parameters for choosing payment inputs
    The new `bark::vtxo::selection::InputSelection` builder controls which
    spendable VTXOs may fund a payment: `max_inputs` caps the number of
    inputs, `exclude` prevents specific VTXOs from being selected, and
    `fee_scheme` makes the selection also cover a selection-dependent fee
    (e.g. lightning or offboard fees), returning the calculated fee
    alongside the selected VTXOs. When the cap binds, selection replaces
    the smallest selected VTXO with a larger candidate instead of giving
    up, so a payment succeeds whenever any compliant set of inputs can
    cover it. `send_onchain` and `estimate_send_onchain` now use this to
    respect the server's `max_offboard_inputs` limit during input
    selection.
    [#2249](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2249)
  - Fail a board when its funding tx is double-spent
    If an input of the board funding tx is spent by a confirmed conflicting
    transaction, the funding tx can never confirm. Once the funding tx drops from
    the mempool the board action re-broadcasts it to probe the inputs: a
    `missing or spent inputs` rejection means a confirmed conflict consumed an
    input, so the board is failed (vtxo dropped, movement marked failed) instead
    of re-broadcasting and retrying forever. A missing parent tx, a competing
    unconfirmed spend, or a transient node rejection keeps the board alive since
    our funding tx could still confirm.
    [#2263](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2263)
  - Post recovery VTXO IDs in batches of 20
    Recovery VTXO IDs are now sent to the mailbox server in chunks of at most
    `MAX_NB_MAILBOX_RECOVERY_IDS` (20) per request.
    [#2267](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2267)
  - Allow canceling a unilateral exit before its final transaction is broadcast
    `Exit::cancel_exit` cancels an exit while its final transaction is still
    unbroadcast; the VTXO stays spendable and a fresh exit can be started later.
    Canceling an already-canceled exit is a no-op. Only live exits are kept in
    memory; finished exits are queried on demand via `Exit::list_finished`.
    [#2270](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2270)
    - **BREAKING:** `ExitState` gains a `Canceled(ExitCanceledState)` variant.
      Exhaustive matches must handle it.
    - **BREAKING:** `ExitError` gains `NotExiting`, `CannotCancelExit` and
      `ExitTxAlreadyBroadcast` variants. Exhaustive matches must handle them.
    - **BREAKING:** `BarkPersister` gains required `get_exit_vtxo_entry` and
      `get_exit_vtxo_entries_with_states` methods. Custom persisters must
      implement them.
    - **BREAKING:** complete or canceled exits no longer appear in `list_exits`,
      use `list_finished` to query them separately.
  - No longer bundle extra VTXOs with refreshes
    When manually refreshing specific VTXOs, `bark` no longer adds other VTXOs that
    merely meet the "should-refresh" criteria into the same round. Callers now get
    exactly the inputs and outputs they asked for, since the maintenance flow already
    handles should-refresh VTXOs on its own.
    [#2271](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2271)
  - Harden block-height arithmetic against overflow and underflow
    Exit-tx status refresh no longer stalls on chains with a tip below 100
    blocks, confirmation counts survive reorg/stale-tip races, and the wallet
    rejects a server advertising an out-of-range `required_board_confirmations`.
    [#2276](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2276)
  - Adds `Exit::list_live` and `Exit::list_all`.
    [#2278](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2278)
    - **BREAKING:** `Exit::get_exit_status` returns `anyhow::Result` instead of
      `Result<_, ExitError>`.
  - Persist the confirmation state of an exit CPFP child transaction
    The stored `ExitTxOrigin` was only written when the child was first
    broadcast or adopted, so it never recorded a later confirmation. A wallet
    reload then reported the child as unconfirmed until the first successful
    chain sync. The origin is now re-persisted whenever its `confirmed_in`
    changes, so exit status is correct immediately after a restart, even
    offline.
    [#2299](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2299)

- `bark-cli`
  - Move the lightning receive token to invoice generation
    `bark lightning invoice --token` authenticates at invoice time, and receive
    status reports the payment's lifecycle state.
    [#2148](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2148)
    - **BREAKING:** removed `--token` from `bark lightning claim`.
  - Deprecate the `--access-token` flag on `bark create`
    Access tokens are not enforced by the server; the flag still accepts a
    value and writes `server_access_token` to `config.toml`, but it is now
    hidden from `--help` output and will be removed in a future release.
    The matching `ark_server_access_token` field on the barkd REST
    `/wallet` (create) request body is also deprecated; sending it remains
    accepted but has no effect on server-side authorization.
    [#2171](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2171)
  - Harden permissions on newly created wallet files
    New wallets now restrict their data directory, secret files and the debug log to the owning user, so other local (non-root) users can no longer read the seed, wallet state, server access token or logged activity. This also covers the `barkd` daemon, which locks down its data directory on creation. Existing wallets are left untouched; bark instead warns on open if their files are accessible to other users.
    [#2194](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2194)
  - Add `bark exit cancel` to abort an exit that hasn't committed on-chain
    `bark exit cancel <vtxo>` cancels a unilateral exit while its final
    transaction is still unbroadcast; the VTXO stays spendable and a fresh
    exit can be started later. Exits in a terminal state (claimed, aborted
    because the VTXO was spent, or canceled) disappear from `bark exit list`
    and remain queryable with the new `--include-finished` flag.
    [#2270](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2270)

- `bark-json`
  - Reshape `LightningReceiveInfo` around the receive lifecycle
    Adds an explicit `state` and `settled_at`, mirroring the send-side status.
    [#2148](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2148)
    - **BREAKING:** added `state: String`, `settled_at: Option<..>`; `htlc_vtxos`
      replaced by `htlc_vtxo_ids`; `payment_preimage` now optional; removed
      `preimage_revealed_at` and `finished_at`.
  - Add BIP 321 URI models
    `Bip321UriRequest`, `Bip321UriQuery` and `Bip321UriResponse` for the new
    `POST /wallet/bip321` endpoint.
    [#2242](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2242)
  - Surface the new `Canceled` exit state
    Mirrors the bark-side support for canceling a unilateral exit before its
    final transaction is broadcast. Adds the `ExitStateKind` discriminator and
    the `ExitCancelResponse` web type used by the new REST cancel endpoint.
    [#2270](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2270)
    - **BREAKING:** `ExitState` gains a `Canceled(ExitCanceledState)` variant.
      Exhaustive matches must handle it.
    - **BREAKING:** `ExitError` gains `NotExiting`, `CannotCancelExit` and
      `ExitTxAlreadyBroadcast` variants. Exhaustive matches must handle them.

- `bark-rest`
  - Long-poll endpoint for wallet notifications
    Clients that cannot hold a persistent websocket can now call
    `GET /api/v1/notifications/wait` to receive buffered `WalletNotification`
    events, optionally filtered by a `since` timestamp. The server holds the
    request open until a notification arrives or the server-side timeout
    elapses, and returns the timestamp of the last pushed event so clients
    can resume polling without gaps.
    [#1960](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1960)
  - Report lightning receive status by lifecycle state
    The status endpoint returns the reshaped `LightningReceiveInfo` with an
    explicit `state` for any known payment hash, instead of a 404 until an HTLC
    arrives.
    [#2148](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2148)
  - Filter wallet history by payment method
    `GET /api/v1/history` now accepts optional `type` and `value` query
    parameters that mirror a payment method's serialized form. Supplying both
    restricts the result to movements involving that single payment method (e.g.
    all payments sent to one address), so integrators no longer have to fetch the
    full history and filter client-side.
    [#2227](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2227)
  - Add `POST /wallet/bip321` to build a unified payment URI
    Bundles an Ark address plus, on request, a BOLT11 invoice (when an amount is
    given) and a fresh on-chain address into one `bitcoin:` URI. The `uppercase`
    query param returns it upper-cased for compact QR encoding.
    [#2242](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2242)
  - Add `POST /v1/fees/offboard` endpoint to estimate offboard fees
    Callers can now estimate the fee for offboarding a specific set of VTXOs to a
    given on-chain address before committing to the operation. The response reports
    the gross amount (total value of the selected VTXOs) and the net amount the user
    receives on-chain after fees, which depend on the destination address type,
    current fee rates, and VTXO expiry.
    [#2250](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2250)
  - Add endpoints to cancel an exit and list finished exits
    `POST /api/v1/exits/cancel/{vtxo_id}` aborts a unilateral exit while its
    final transaction is still unbroadcast; canceling an already-canceled exit
    is a no-op. It returns 404 if the VTXO has no exit and 400 once the exit
    can no longer be canceled. Finished exits (claimed, aborted because the
    VTXO was spent, or canceled) drop out of `GET /exits/status` and are served
    by the new `GET /api/v1/exits/status/finished` instead.
    [#2270](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2270)
    - **BREAKING:** `GET /exits/status` now returns only live exits and its
      OpenAPI operation was renamed from `get_all_exit_status` to
      `get_live_exit_status`, renaming the method in generated clients.
  - Rework the exit status endpoints
    Adds `GET /exits/status/all`, `GET /exits/status/live` and
    `GET /exits/status/vtxo/{vtxo_id}`. `GET /exits/status` is deprecated and
    permanently redirects to `/exits/status/all`; `GET /exits/status/{vtxo_id}`
    is deprecated but still served. Both will be removed in a future release.
    The by-VTXO endpoints now also serve finished exits. The previously
    released operation IDs move to the new endpoints, so regenerated clients
    keep working unchanged.
    [#2278](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2278)

- `bip321`
  - Add `Bip321Uri::checked_uppercase`
    Renders an all-upper-case URI for compact QR encoding; returns `None` when
    case-sensitive data (label, message, `pop`, custom param, base58 address)
    would be corrupted.
    [#2242](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2242)

- `bitcoin-ext`
  - Add `AddressExt::is_uppercasable`
    Reports whether an address uses case-insensitive bech32(m) and can be safely
    upper-cased; base58 and unknown witness versions are treated as not.
    [#2242](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2242)

- `server`
  - Make offboard sessions safely retryable
    A client that lost the `finish_offboard` response can retry the request
    and receive the same signed tx back for as long as the session lives.
    `prepare_offboard` validates input spendability before the request
    parameters (fee rate freshness, amounts, the address blocklist), so
    clients recovering a lost session can tell spent inputs apart from a
    request that can no longer succeed.
    - Session expiry and uncommitted offboard txs are now swept on a fixed
      interval, configurable via `offboard_check_interval` (default 1s,
      validated to not exceed `offboard_session_timeout`)
    [#2085](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2085)
  - Return correct error codes for lightning receive anti-dos checks
    Invalid attestations, unspendable proof vtxos and unknown tokens now surface
    as `badarg`/`not_found` instead of a generic internal error.
    [#2148](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2148)
  - add config variable `bitcoin_address_blocklist_refresh_interval`
    - specifies the interval at which the blocklist file is refreshed
    - defaults to 1 hour
    [#2169](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2169)
  - Deprecate the `rpc.access_token` telemetry attribute
    Access tokens are not enforced by the server; the attribute is no longer a
    reliable signal. The `RPC_ACCESS_TOKEN` constant and its use on the gRPC
    request span are marked `#[deprecated]` and will be removed in a future
    release. Any dashboard or LogQL query relying on `rpc.access_token` should
    migrate or remove the filter.
    [#2171](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2171)
  - Authenticate the `PostRecoveryVtxoIds` mailbox endpoint
    Posts to a recovery mailbox can now carry a signed proof of mailbox
    ownership, verified like the read path, so third parties can no longer
    write to a mailbox they don't own. The authorization stays optional for
    now to keep older clients working.
    [#2234](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2234)
  - Harden lightning payment-attempt settlement against optimistic-lock races
    `process_payment_attempt` now runs the attempt update before marking linked
    HTLC-send vtxos `ln-spent`, and only mutates the vtxos when the update
    actually committed, so a lost optimistic-lock race no longer spends vtxos
    for an attempt we did not transition. Because the attempt has already
    transitioned to `Succeeded` by the time the vtxos are marked,
    `mark_htlc_send_vtxos_ln_spent` no longer filters linked attempts by
    status. The query also re-checks the live `spend_state` during the
    `UPDATE`, so a concurrent transition of a linked vtxo cannot be
    clobbered.
    [#2241](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2241)
  - Make `prepare_offboard` idempotent for identical retries
    A client that lost the response to a `prepare_offboard` request (e.g. it
    crashed before persisting it) can re-send the exact same request and get
    the pending session's response replayed — the same unsigned offboard tx
    and the same cosign nonces — instead of being rejected because its own
    session still holds the vtxo locks. Attestations are re-verified before
    replaying, so only the vtxo owner can retrieve the session.
    [#2252](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2252)
  - Expire abandoned offboard sessions on schedule
    Pending offboard sessions were never swept, so an abandoned session kept
    its input vtxos and wallet UTXOs locked until a restart. A handful of
    abandoned sessions — one per wallet UTXO — could lock the entire rounds
    wallet and starve round funding. Sessions now expire after
    `offboard_session_timeout`, and the sweep runs at least as often as
    sessions can expire, so timeouts shorter than 30 seconds take effect at
    their configured resolution.
    [#2252](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2252)
  - Use the fast fee rate for the round funding transaction
    The on-chain round funding tx now targets a 1-block confirmation instead
    of 3-blocks.
    [#2256](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2256)
  - remove the GetFreshRounds and GetRound gRPC functions
    - no longer used by our client since beta times
    [#2265](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2265)
  - Limit mailbox recovery requests to 20 VTXO IDs
    `post_recovery_vtxo_ids` now rejects a request carrying more than 20 VTXO
    IDs (the new `MAX_NB_MAILBOX_RECOVERY_IDS` constant) with a bad-argument
    error.
    [#2267](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2267)
  - Validate CLN HTLC expiry heights instead of truncating
    The hold-plugin boundary now bounds the incoming HTLC expiry and final
    CLTV delta rather than silently truncating them into the accept/cancel
    settlement decision.
    [#2276](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2276)

# v0.3.0

- `bark`
  - Don't commit a VTXO to a unilateral exit until the chain is actually broadcast
    Starting an exit no longer immediately marks the VTXO as `Spent` and writes a
    `Successful` exit movement. Instead the VTXO stays spendable until every exit
    transaction has been broadcast, at which point it transitions to the new
    `VtxoState::Exited`. The exit movement is created `Pending` and only finalizes
    when the exit reaches `Claimed` (`Successful`) or detects the VTXO has been
    consumed elsewhere first (`Canceled`, via the new `ExitState::VtxoAlreadySpent`
    terminal state). Users can now refresh, send, or otherwise spend a VTXO that's
    been queued for exit, and the exit progress code will detect the change and
    cancel itself cleanly.
    [#2117](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2117)
    - **BREAKING:** `VtxoState` and `VtxoStateKind` gain an `Exited` variant.
      Exhaustive matches must handle it. `Exited` is reported by the server as
      refused (like `Spent`) but is distinct: it indicates the user moved the
      funds onchain rather than forfeiting them in the protocol.
    - **BREAKING:** `ExitState` gains a `VtxoAlreadySpent(ExitVtxoAlreadySpentState)`
      terminal variant. Exhaustive matches must handle it.
    - **BREAKING:** `ExitVtxo::new` now takes an `Option<MovementId>` parameter so
      the exit can drive its movement to completion..
    - **BREAKING:** Do not upgrade to this release if you have an in-progress exit
      on mainnet and are using a `StorageAdaptor` backend like `indexeddb` instead
      of `sqlite`. Only new exits will work, finish your current exits before
      upgrading. All other bark clients are unaffected and are safe to upgrade.
  - Send an `x-user-agent` header on every Ark RPC
    Bark now identifies itself to the Ark server on every request, defaulting
    to `bark/<version>` for the CLI and `barkd/<version>` for the daemon.
    Integrators embedding the `bark` crate (FFI bindings, WASM wallets, custom
    apps) can override the value via the new `Config.user_agent` field or
    `ServerConnectionBuilder::user_agent()`, so server-side telemetry can
    attribute traffic per implementation.
    [#2170](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2170)
    - **BREAKING:** `bark::Config` gained a `user_agent: Option<String>` field.
      Code that constructs `Config` via struct literal must now supply
      `user_agent: None` (or a value) explicitly. Code using
      `Config::network_default(...)` or TOML deserialization is unaffected.
  - Maintenance refresh no longer gets stuck on a single unusable VTXO
    Previously, one input the server rejected (e.g. spent server-side while the
    wallet still considered it spendable) failed the whole atomic refresh batch on
    every maintenance run, so healthy expiring VTXOs never refreshed and would
    eventually become exit-only. Maintenance (both interactive and delegated) now
    drops the inputs the server rejects and retries with the rest; the interactive
    path re-submits to the same in-flight round attempt. Explicit, developer-initiated
    refreshes still fail wholesale rather than silently dropping a caller's selection.
    - **BREAKING:** `Wallet::maybe_schedule_maintenance_refresh` has been removed.
      Interactive maintenance now actively joins the in-flight round attempt: the
      daemon does so on the round Attempt event, and the blocking
      `Wallet::maintenance_refresh` does so inline.
    - Adds `Wallet::get_vtxos_to_refresh_with_excluded`, which selects refreshable
      VTXOs while skipping a caller-supplied set (used to drop server-rejected inputs).
    [#2217](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2217)
  - add `bark::persist::platform_default`
    [#2076](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2076)
  - refactor `bark::lock_manager::platform_default` to take optional datadir and fingerprint
    [#2076](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2076)
  - replace `WalletSeed::new` with `new_from_seed` and `new_from_mnemonic`
    [#2076](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2076)
  - refactor `Wallet::open` and `Wallet::create` variants in single methods with optional args
    - remove `Wallet::open_with_daemon`
    - remove `Wallet::open_with_exits`
    - remove `Wallet::create_with_exits`
    [#2076](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2076)
  - remove `Wallet::bark_wallet.require_chainsource_version`
    [#2076](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2076)
  - Fix arkoor receives being double-counted in wallet history
    When several consumers of one wallet processed the mailbox at the same time
    (the daemon's always-on stream alongside a periodic sync, or concurrent REST
    `/sync` and `/sync/mailbox` requests), each could win the receive dedup check
    before the others stored, recording its own movement for the same arkoor. The
    received VTXO still landed once, but the receive showed up multiple times in
    history. Processing now serializes the dedup per wallet so the receive is
    recorded exactly once.
    [!2168](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2168)
  - Add support for paying raw LNURL-pay links
    Bark can now pay bech32-encoded LNURL-pay links (`lnurl1…`).
    `Wallet::parse_payment_request` parses them and the new `Wallet::pay_lnurl`
    resolves the endpoint to a BOLT11 invoice and pays it.
    [#2176](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2176)
  - Detect and recover VTXOs that were force-exited on-chain
    When a VTXO is pushed on-chain without the user asking for it — e.g. the
    server's watchman progressing a shared exit tree, or another party's
    unilateral exit dragging a parent on-chain — the server then rejects spending
    it, yet a plain sync still reported it as `Spendable`, leaving the user stuck
    with funds that are only recoverable by a manual unilateral exit. `Wallet::sync`
    now scans spendable VTXOs on each new chain tip and routes any whose funding
    transaction is already on-chain into the unilateral-exit flow, so the funds can
    be completed and claimed on-chain automatically.
    [#2208](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2208)
    - Adds `Wallet::sync_force_exited_vtxos`, run automatically by `Wallet::sync`.
  - fix disconnecting from Ark server every 10 minutes
    - streaming connections now can live for one hour
    [#2213](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2213)
  - Protect Lightning-received VTXOs from being force-exited
    When claiming a Lightning receive, bark now builds the claim arkoor with a
    checkpoint. The checkpoint gives the server's watchman a stopping point: if
    the parent VTXO is ever dragged on-chain, the watchman broadcasts the
    checkpoint instead of progressing all the way to your claimed VTXO and
    exiting it against your will. Previously such a force-exit left the VTXO
    unspendable off-chain while the server rejected any refresh of it.
    [#2214](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2214)
  - Flag Arkade addresses as an unsupported payment option
    `Wallet::parse_payment_request` now parses Arkade addresses (used directly or
    in the `ark` parameter of a BIP 321 URI) into a `PaymentMethod::Custom` option
    flagged with `InvalidArkAddress(ServerMismatch)`, instead of failing the
    whole parse. This lets callers present the option and explain why it can't
    be paid.
    Adds a public `bark::payment_request::ArkAddressType` enum with `Bark` and
    `Arkade` variants, used to distinguish the two address forms when parsing.
    [#2220](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2220)
  - Increase incremental sync speed of esplora/mempool.space
    Previously we were checking the status of every transaction the wallet had ever seen. Now we only query
    transactions which are not deeply confirmed, as of today that means 100 confirmations.

- `bark-cli`
  - Accept LNURL-pay links as a payment destination
    `bark pay` and `bark lightning pay` now pay raw LNURL-pay links (`lnurl1…`),
    like lightning addresses (an amount is required).
    [#2176](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2176)
  - Reject Arkade addresses with an explicit error
    `bark send` now fails with "Ark address is for different server" when given
    an Arkade address, instead of falling through to the generic "not a valid
    destination" error. The destination help text now lists `ark addresses` in
    place of `VTXO pubkeys`.
    [#2220](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2220)

- `bark-json`
  - Surface the new `Exited` VTXO state and `VtxoAlreadySpent` exit state
    Mirrors the bark-side changes that decouple "the user moved this VTXO onchain"
    from "the protocol forfeited this VTXO" and that surface an explicit terminal
    state when an exit can't proceed because the VTXO has already been consumed.
    [#2117](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2117)
    - **BREAKING:** `VtxoStateInfo` gains an `Exited` variant.
    - **BREAKING:** `ExitState` gains a
      `VtxoAlreadySpent(ExitVtxoAlreadySpentState)` variant.

- `bark-rest`
  - Accept LNURL-pay links as a payment destination
    The wallet and lightning pay endpoints now pay raw LNURL-pay links (`lnurl1…`)
    passed as `destination`, like lightning addresses (an amount is required).
    [#2176](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2176)
  - Reject Arkade addresses with an explicit error
    The wallet send endpoint now returns "Ark address is for different server"
    when an Arkade address is passed as `destination`, instead of falling
    through to the generic "not a valid destination" error.
    [#2220](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2220)
  - fix missing `exit_depth` field on VTXO listings
    [#2225](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2225)

- `server`
  - Attribute gRPC traffic per client implementation
    All `second_grpc_*` metrics (request duration, in-progress, error counters)
    gain a `client` label derived from the `x-user-agent` header sent by bark.
    The version suffix is stripped so all releases of a given client share a
    bucket (e.g. `bark/0.2.3` and `bark/0.2.4` both report as `client="bark"`).
    Dashboards can now split board / lightning / round volume per client.
    Client names not seen before are admitted dynamically up to a bounded
    process-wide budget; further unique names roll up into `other` and the
    team is paged via an error-level log.
    [#2170](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2170)
  - Allow checkpointed Lightning-receive claims
    The `claim_lightning_receive` handler now derives the arkoor checkpoint
    requirement from the negotiated protocol version: clients speaking
    `PROTOCOL_VERSION_LN_RECEIVE_CHECKPOINT` or later must claim with a
    checkpoint, so the watchman stops at the checkpoint instead of force-exiting
    the claimed leaf. Older clients keep claiming without checkpoints, so the
    change stays backward compatible.
    [#2214](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2214)
  - Reject round participations that reference unusable input VTXOs
    When a participation (interactive `submit_payment` or delegated
    `submit_round_participation`) references inputs that are already spent or being
    exited, the server now returns `InvalidArgument` listing every offending VTXO
    id in the `identifiers` gRPC metadata, rather than failing the whole round
    opaquely. Clients can then drop exactly those inputs and retry.
    [#2217](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2217)

- `server-rpc`
  - rename field `unblinded_id` to `mailbox_id` in `MailboxRequest` and `PostRecoveryVtxoIdsRequest`,
    content stays identical
    [#2199](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2199)
  - Add protocol version 3, `PROTOCOL_VERSION_LN_RECEIVE_CHECKPOINT`
    Bumps `MAX_PROTOCOL_VERSION` to 3. On this version the Lightning-receive
    claim is checkpointed, which lets the server's watchman stop at the
    checkpoint rather than force-exiting a freshly claimed VTXO. Version
    negotiation keeps older clients and servers interoperable.
    [#2214](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2214)
  - Add `StatusExt::rejected_vtxos()` to extract the VTXO ids the server flagged as
    unusable from a rejection's `identifiers` metadata
    [#2217](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2217)

# v0.2.5

Special thanks to Greg Sanders and Floppy for privately disclosing
vulnerabilities fixed in this release.

- `ark-lib`
  - bugfix: reject VTXOs with output_idx out of range
    [#2183](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2183)

- `bark`
  - fix potential panic on bad round data from server
    [#2181](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2181)
  - prevent panics in some of the daemon procedures to halt entire process
    [#2181](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2181)
  - protect against accidental nonce re-use when failing to persist after signing round
    - no longer support progressing round while sleeping intermittently: bark needs to stay
  	in memory between signing up for the round and signing the vtxo proposal
    [#2182](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2182)

- `server`
  - bugfix: correctly check user-provided HTLC expiry value for LN receive
    [#2184](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2184)
  - various fixes in feerate update logic
    - fix reverse clamp in max_fee_rate
    - prevent double update on fallback
    - use ECONOMICAL instead of CONSERVATIVE
    - move the slog to a better place
    [#2185](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2185)

# v0.2.4

- `bark`
  - Include claimable exits in the `pending_exit` balance
    Funds from unilateral exits that have reached the claimable state are now
    reported as part of the pending exit balance, so they remain visible to
    users until they are spent on-chain.
    [#2161](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2161)
  - Stop auto-exiting Lightning receives when the claim fails
    A failed HTLC claim (e.g. transient server errors after the retry budget
    is exhausted) no longer triggers an automatic unilateral exit of the HTLC
    VTXOs. The receive stays pending so the claim can be retried, and
    `Wallet::attempt_lightning_receive_exit` can be used to explicitly fall
    back to an on-chain exit.
    [#2174](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2174)

- `bark-cli`
  - add `--no-auth` option to barkd to disable auth
    This can be used together with the CORS setting when shipping in a container
    as a web application.
    [#2157](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2157)
  - fix multi-input offboards
    - add fixup for old clients that got stuck by doing an offboard
    [#2175](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2175/)

- `server`
  - Fold `watchman_vtxo_frontier` columns onto the `vtxo` table
    Adds `frontier_at`, `confirmed_height`, `onchain_spent_height`, and
    `onchain_spent_txid` to `vtxo` (and `vtxo_history`), copies existing
    rows over, and drops `watchman_vtxo_frontier`. A single row lock now
    serializes captaind/watchmand transitions that previously spanned two
    tables.
    [#2112](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2112)
  - add `max_fee_rate` config option to specify maximum fee rate
    (this is to protect against fee estimators returning insane fee rates)
    [#2154](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2154)
  - add `bitcoin_address_blocklist` config variables to `captaind` and `watchmand`
    - refers to a file name with blocklist of addresses, loaded on startup
    - offboards to blocked addresses are rejected
    - boards with funds coming from blocked addresses are rejected
    - funds coming to internal wallets coming from blocked addresses are ignored
    [#2155](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2155)
  - avoid spurious error log when a client submits an oversized BOLT 11 invoice description, rejecting it with `badarg` instead
    [#2164](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2164)

# v0.2.3

- `bark`
  - add `sqlite-bundled` compile feature
    [#2122](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2122)
  - Change exit claim transactions to v2
    Initially when claiming an exit, bark produced a v3 transaction which is intended to be a TRUC. This is unnecessary
    and added unnecessary restrictions to the claim process. This has now been fixed.
    [#2149](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2149)
  - Don't auto-exit unfinished lightning receives.
    We've had a few instances of incoming lightning payments getting exited unnecessarily. Instead we should leave this
    up to developers whilst we implement better logic.
    [#2152](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2152)
    - Introduces `Wallet::attempt_lightning_receive_exit` which can be used to forced an exit of an unfinished
      lightning receive, provided the preimage has been revealed and HTLCs have been received.
  - Let developers opt failed lightning sends into exiting their HTLCs
    When a lightning send fails and HTLC revocation also fails, bark no longer
    force-exits the HTLC vtxos automatically. Stuck sends can be inspected via
    `Wallet::stuck_failed_lightning_sends`, and `Wallet::allow_lightning_send_to_exit`
    opts an individual send into auto-exiting once its HTLCs approach expiry.
    [#2153](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2153)
    - **BREAKING:** New `Progress::RevocationStuck` variant on the lightning
      send state machine; any exhaustive matches on `Progress` must add an arm.
    - **BREAKING:** New `allow_exit_of_htlcs: bool` field on `LightningSend`.

# v0.2.2

- `bark`
    - Make outgoing lightning sends crash-safe via the wallet action executor
      Lightning sends are now persisted as a single `WalletActionCheckpoint`
      row and driven across crashes by the executor. Settled payments are recorded
      in a new `bark_paid_invoice` fact table and kept forever, letting the wallet
      answer "is this invoice paid?" without consulting the server.
      [#2062](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2062)
        - **BREAKING:** `Wallet::pay_lightning_invoice` and
          `Wallet::pay_lightning_offer` take a new `wait: bool` parameter that
          blocks until the send reaches a terminal state. Pass `false` to
          return as soon as the payment is initiated and poll
          `Wallet::lightning_send_state` for progress.
        - **BREAKING:** `Wallet::check_lightning_payment` was removed. Use
          `Wallet::lightning_send_state` (returns `LightningSendState::Unknown
      | InProgress(LightningSend) | Paid(PaidInvoice)`),
          `Wallet::lightning_send_checkpoint`, or `Wallet::is_invoice_paid`
          instead.
    - the wallet maintenance will now do rounds JIT, so it will not lock VTXOs
      while waiting for a round to start
        - if any existing rounds were ongoing and can be cancelled, it will cancel them first;
          this is done to clean up probably stuck rounds and later refresh again
          [#2113](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2113)
    - Surface `is_cpfp` on `bark::onchain::WalletTxInfo`
      Flags transactions that spend a P2A fee anchor — typically the wallet's
      own CPFP children bumping an exit transaction. Lets consumers label or
      hide these internal txs in user-facing transaction lists.
      [#2119](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2119)
    - Make unilateral exit progress resilient to chain-source hiccups and surface real failures
      A single transaction failing its status refresh inside the exit transaction
      manager no longer aborts the whole progress call — the failure is logged and
      the rest of the txs continue, and the next sync tick retries. When a
      progress run genuinely fails at a level that can't be attributed to a
      specific VTXO (chain source unreachable, refresh tip retrieval failed),
      `bark exit progress` now emits the error on a new top-level field of its
      JSON response instead of dying with an unstructured stderr message, so
      callers that scrape the JSON (tests, automation scripts) can match on the
      variant and decide whether to retry.
      [#2120](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2120)

- `bark-cli`
    - change log level for bitcoind client to DEBUG
      [#2126](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2126)

- `barkd`
    - Add `GET /api/v1/wallet/mnemonic` endpoint
      Returns the wallet's BIP-39 mnemonic phrase so operators can back up
      the mnemonic without reading `{datadir}/mnemonic` off the host.
      Exposed by default; disable with `BARKD_EXPOSE_MNEMONIC=false` (or
      `--expose-mnemonic=false`), in which case the endpoint responds 404.
      [#2114](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2114)
    - Add `is_cpfp` field to `GET /api/v1/onchain/transactions`
      A single exit can produce several child-pay-for-parent transactions
      that fee-bump the exit's anchor outputs. They show up in the wallet's
      tx list and are confusing for most end users. This flag gives client
      developers a hook to label or hide those internal txs.
      [#2119](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2119)
    - make swagger ui optional with `swagger-ui` compile feature
      [#2123](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2123)

- `bark-json`
    - Drop `LightningSendInfo` and `LightningMovement` from CLI for a compact
      `LightningSendStatus { payment_hash, state, invoice, preimage }` instead.
      [#2062](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2062)
        - **BREAKING:** `bark_json::cli::LightningSendInfo` removed.
        - **BREAKING:** `bark_json::cli::LightningMovement` removed (it only
          wrapped `LightningReceiveInfo` / `LightningSendInfo`).
    - Add `MnemonicResponse` for the new `GET /api/v1/wallet/mnemonic` endpoint
      [#2114](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2114)
    - `bark onchain transactions` now emits the rich `WalletTxInfo` shape
      The CLI's onchain tx list now matches the REST endpoint: it includes
      `onchain_fee_sat`, `balance_change_sat`, `confirmation`, and the new
      `is_cpfp` flag, rather than just `{txid, tx}`.
      [#2119](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2119)
        - **BREAKING:** `bark onchain transactions` JSON output shape changed
          from `TransactionInfo` (`{txid, tx}`) to `WalletTxInfo`. Scripts
          parsing the CLI output need to adapt.
        - Adds `is_cpfp` to `bark_json::primitives::WalletTxInfo`.
    - Surface top-level exit progress errors on `ExitProgressResponse`
      `ExitProgressResponse` gains an optional `error: Option<ExitError>` field
      for failures that aren't attributable to a specific exit (e.g. the chain
      source becoming unavailable or the exit manager failing to refresh its
      view of pending transactions). Per-exit problems still live on each
      `ExitProgressStatus`; this slot fills in the gap for global failures so
      consumers can distinguish "one VTXO had a problem" from "the whole
      progress run hit a transient issue".
      [#2120](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2120)

- `bark-rest`
    - Add `GET /api/v1/wallet/mnemonic` endpoint
      Returns the wallet's BIP-39 mnemonic phrase via a new `OnGetMnemonic`
      hook on `ServerState`. Embedders that don't supply the hook get a
      404 on this endpoint.
      [#2114](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2114)
        - **BREAKING:** `RestServer::start` now takes a `ServerState` instead
          of individual wallet/auth/hook arguments. Build it via
          `ServerState::builder()`.
        - **BREAKING:** `ServerState::new` removed in favor of
          `ServerState::builder()`.

- `server`
    - Return `badarg` when a client tries to spend an unspendable VTXO
      `VtxoState::check_spendable` and the oor / round / offboard spend-update
      paths now surface unspendable or banned VTXOs as `badarg` instead of
      generic internal errors.
      [#2062](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2062)

# v0.2.1

- `bark`
    - Add BIP 321 URI builder to bark wallet
      Bark wallets can now construct BIP 321 `bitcoin:` URIs that bundle Ark,
      Lightning, and onchain destinations into a single payment request via
      `Wallet::bip321_uri`. The new `GetAddress` trait abstracts onchain
      address generation so callers can plug in any onchain wallet backend.
      [#1997](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1997)
    - Refactor unilateral exit to be wallet-agnostic
      The unilateral exit driver no longer constructs and broadcasts CPFP child
      transactions internally. Callers fetch pending CPFP work via
      `Exit::exits_needing_cpfp` (which returns `ExitCpfpRequest` items, including
      `min_fee_for_rbf` when an RBF replacement is needed) and submit signed
      children back via `Exit::provide_cpfp_tx`. The state machine now pauses at
      CPFP boundaries instead of racing internal broadcasts, letting third-party
      wallets drive exits with their own fee policy and signer. Callers using
      bark's bundled BDK onchain wallet can keep the old one-shot behaviour via
      `Exit::progress_exits_onchain`.
      [#2032](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2032)
        - **BREAKING:** `ExitTxStatus` variants reshaped — see the `bark-json`
          changelog for the wire-format changes.
        - **BREAKING:** `ExitError::InsufficientFeeToStart` removed; fee
          insufficiency surfaces via `ExitCpfpRequest.min_fee_for_rbf` instead.
        - New `ExitError::DatabaseChildStoreFailure` reported when persisting a
          CPFP child transaction fails.
    - Track mempool RBF info for every exit CPFP child, not just downloaded ones
      Effective fee rate and total package fee are now stored on
      `ChildTransactionInfo.fee_info` (`Option<FeeInfo>`) and refreshed by the
      next sync after a child enters the mempool — regardless of whether it was
      built by our wallet or downloaded from the chain source. This lets the
      state machine make consistent RBF decisions without re-deriving fee info
      from `ExitTxOrigin`.
      [#2032](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2032)
        - **BREAKING:** `ExitTxOrigin::Mempool` is now a unit variant; fee data
          moved off of origin onto `ChildTransactionInfo.fee_info`. Persisted
          state from older versions still deserializes cleanly (extra
          `fee_rate_kwu` / `total_fee` fields on Mempool origins are ignored).
        - New `FeeInfo { fee_rate, total_fee }` struct re-exported from
          `bark::exit`.
        - New `ExitTxOrigin::with_confirmed_in(...)` helper that updates an
          origin given its current confirmation state.
        - New `ExitChildStatus.fee_info: Option<FeeInfo>` field.
    - Resolve esplora-electrs lag during exit CPFP RBF
      When the chain source reports a different unconfirmed spending tx than
      our locally-broadcast wallet child (typically because esplora-electrs
      hasn't indexed our broadcast yet), the transaction manager now tries
      to (re-)broadcast our package first. If Bitcoin Core accepts it — or
      reports it as `AlreadyKnown` — we keep our wallet child. If broadcast is
      rejected (`InsufficientReplacementFee`, `MissingOrSpentInputs`, etc.)
      we accept the chain's tx. This avoids silently downgrading a freshly
      broadcast high-fee RBF to a stale lower-fee child returned by a lagging
      indexer.
      [#2032](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2032)
    - Include the timezone offset in terminal log timestamps
      Terminal log lines now show the UTC offset (e.g. `+02:00`) alongside the local time.
      [#2083](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2083)
    - Avoid panic when failing to download an exit transaction
      [#2087](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2087)

- `bark-json`
    - Reshape `ExitTxStatus` and `ExitError` for the unilateral exit refactor
      The exit state machine no longer exposes intermediate "machine action"
      states; statuses now describe the tx itself.
      [#2032](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2032)
        - **BREAKING:** `ExitTxStatus::NeedsSignedPackage` and
          `ExitTxStatus::NeedsReplacementPackage` are replaced by
          `ExitTxStatus::AwaitingCpfpBroadcast`. The `min_fee_rate` /
          `min_fee_rate_kwu` / `min_fee` hints on `NeedsReplacementPackage` are
          gone — RBF fee requirements are surfaced through
          `bark::exit::ExitCpfpRequest.min_fee_for_rbf` at request time.
        - **BREAKING:** `ExitTxStatus::NeedsBroadcasting` and
          `ExitTxStatus::BroadcastWithCpfp` are replaced by
          `ExitTxStatus::AwaitingConfirmation` (same `child_txid` and `origin`
          fields).
        - **BREAKING:** `ExitError::InsufficientFeeToStart` removed.
        - New `ExitError::DatabaseChildStoreFailure { error }` variant.
    - Decouple mempool RBF info from `ExitTxOrigin`
      The `ExitTxOrigin::Mempool` variant is now a unit variant. Effective fee
      rate and total package fee are exposed on `ChildTransactionInfo.fee_info`
      (a new `FeeInfo { fee_rate, total_fee }` struct) and tracked for any
      unconfirmed child regardless of how it entered our state — wallet-built
      children get fee info populated by the next sync, not just children we
      downloaded from the mempool.
      [#2032](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2032)
        - **BREAKING:** `ExitTxOrigin::Mempool` no longer carries `fee_rate` /
          `fee_rate_kwu` / `total_fee` fields. Read these from
          `ChildTransactionInfo.fee_info` instead.
        - New `FeeInfo` struct with `fee_rate` (serialized as
          `fee_rate_sat_per_kvb`, matching the unit used elsewhere in
          `bark-json`) and `total_fee` (serialized as `total_fee_sat`).
        - New optional `ChildTransactionInfo.fee_info: Option<FeeInfo>`.

- `bark-rest`
    - Fix OpenAPI spec for `GET /api/v1/history`
      The spec previously wrongly advertised the endpoint at `/api/v1/history/`,
      which broke generated clients.
      [#2099](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2099)

# v0.2.0

- `ark-lib`
    - Add `LnSendFinished` mailbox type
      New mailbox message type for lightning send completion notifications.
      [#1889](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1889)
    - Validate VTXO policy block heights and deltas at decode time
      `Vtxo::decode` and `VtxoPolicy::decode` now reject `expiry_height`,
      `htlc_expiry`, `exit_delta`, and `htlc_expiry_delta` values outside the
      policy-safe range. Previously a malicious server could panic the client with
      `htlc_expiry` at or above `LOCK_TIME_THRESHOLD`, or trigger `u16` arithmetic
      overflow with large `htlc_expiry_delta` or `exit_delta`.

      The same bounds are exposed as `MAX_BLOCK_HEIGHT`, `MAX_BLOCK_DELTA`,
      `check_block_height`, and `check_block_delta` in `ark::vtxo::policy` for
      reuse at other deserialization boundaries (gRPC, postgres). Two
      `const _: () = assert!(...)` lines anchor the headroom invariant so all
      in-codebase compositions (`exit_delta + htlc_expiry_delta`, `2 * exit_delta`,
      `confirmed_at + 2 * exit_delta`) stay within their integer types.

      The `arithmetic_side_effects` clippy lint is now `deny` for the `ark-lib`
      crate, requiring every arithmetic site to use `checked_*` / `saturating_*` /
      `wrapping_*` rather than raw operators. All other clippy lints are
      explicitly allowed (`clippy::all = "allow"` with priority override), so
      this is the only rule enforced. The lint is local to this crate; other
      workspace members may adopt it later. Workspace release profile sets
      `overflow-checks = true` as defense in depth for any sites the lint misses.
      [#2046](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2046)

    - Reject empty pubkey list in cosigned `GenesisTransition` decode
      `GenesisTransition::decode` now returns a `ProtocolDecodingError` when a
      cosigned variant carries an empty pubkey vector. A `CosignedGenesis` with
      no pubkeys violates the type's invariant and downstream callers assume at
      least one cosigner.
      [#2046](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2046)
    - Expose standalone genesis encoding for `Vtxo<Full>`
      Adds `Vtxo::<Full, P>::encode_genesis` / `serialize_genesis` and the
      inverse `Vtxo::<Bare, P>::decode_genesis` / `with_genesis`.
      [#2050](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2050)
    - Reject decoding a `Vtxo<Full>` from `Vtxo<Bare>` data
      Previously a `Vtxo<Bare>` serialization could be silently decoded as a `Vtxo<Full>`,
      yielding a "full" VTXO with an empty genesis chain. `Vtxo<Full>` now rejects such
      input, except for virtual VTXOs that wrap an onchain UTXO (where `point` equals
      `chain_anchor`), which legitimately carry no genesis items.
      [#2072](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2072)
        - Added `Vtxo::<Full>::deserialize_with_genesis` to reassemble a full VTXO from
          separate bare and genesis byte buffers (e.g. when the two halves are stored
          independently).
        - Added `VtxoValidationError::MissingGenesisItems` and
          `VtxoValidationError::UnexpectedGenesisItems`.

- `bark`
    - Split board flow into `board_funding_address` + `board_tx`
      Allows external wallets to build and sign the funding transaction themselves,
      then complete the board via `board_tx` with a pre-signed PSBT. The PSBT is
      validated to ensure it pays to the correct funding address and meets the
      minimum board amount.
      [#1766](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1766)
    - Handle lightning send finished mailbox notifications
      Bark now processes server notifications when a lightning send payment
      completes, allowing prompt handling of success or failure without polling.
      [#1889](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1889)
    - Fetch offboard fee rate from dedicated endpoint
      Bark now calls `GetOffboardFeeRate` directly instead of re-fetching the
      entire `ArkInfo` on a TTL to get the current mempool fee rate.
      [#2029](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2029)
    - Reconnect mailbox and round-event streams gracefully on idle timeout
      Streaming connections killed by a proxy idle timeout are now silently
      reconnected instead of treated as server failures. This prevents the
      daemon from unnecessarily marking the server as disconnected or giving
      up on the mailbox stream after prolonged idle periods.
      [#2040](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2040)
    - Add a `LockManager` to prevent race-conditions.
      [#2042](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2042)
        - **BREAKING:** `Wallet::create`, `Wallet::open`,
          `Wallet::create_with_onchain`, `Wallet::open_with_onchain`, and
          `Wallet::open_with_daemon` gain a `lock_manager: Box<dyn LockManager>`
          parameter.
        - **BREAKING:** the `pid-lock` Cargo feature is gone; bark-cli now takes
          its datadir lock via `lock_manager::platform_default`.
    - Slim down VTXO listings by storing the genesis item chain separately
      Bark now stores each VTXO as a small "bare" blob plus a separate genesis
      blob. Listings, balance computations, coin selection, and refresh-strategy
      checks load only the bare form (~200 B per VTXO regardless of exit depth)
      along with two cached scalars (`exit_depth`, `exit_tx_weight`); For wallets
      with many or deep VTXOs this can be a 20–100x reduction in resident memory
      across the read-only hot paths.
      [#2050](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2050)
        - **BREAKING:** `WalletVtxo` now holds `Vtxo<ark::vtxo::Bare>` instead of
          `Vtxo<ark::vtxo::Full>`, plus two cached fields: `exit_depth: u16` and
          `exit_tx_weight: bitcoin::Weight`. Use the new `Wallet::get_full_vtxo`
          (or `BarkPersister::get_full_vtxos` for batches) to obtain the full
          VTXO with its exit chain when needed.
        - **BREAKING:** `Exit::start_exit_for_vtxos` now accepts
          `&[impl Borrow<Vtxo<Bare>>]`, replacing the old
          `&[impl Borrow<Vtxo<Full>>]` signature.
        - Adds `BarkPersister::get_full_vtxo` and `BarkPersister::get_full_vtxos`
          for SDK consumers implementing custom storage backends.
        - Adds migration `0029_split_vtxo_genesis` which splits existing
          `bark_vtxo.raw_vtxo` blobs into `raw_bare`/`raw_genesis` columns and
          backfills the cached `exit_depth`/`exit_tx_weight` columns.
    - move `Wallet::chain_source` static constructor to `Config::chain_source`
      [#2052](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2052)
    - replace `Wallet::chain` field with `Wallet::chain` getter method
      [#2052](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2052)
    - replace `Wallet::exit` field with `Wallet::exit_mgr` getter method
        - the getter returns the `Exit` struct directly without `RwLock`
          [#2052](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2052)
    - replace `Wallet::movements` field with `Wallet::movements_mgr` getter method
      [#2052](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2052)
    - make `Wallet` internally wrap an Arc so that it can be cloned
        - remove `Arc<Wallet>` from the API and replace with `Wallet`
          [#2052](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2052)

    - Richer onchain transaction listing in the REST API
      `GET /onchain/transactions` now returns `onchain_fee_sat` (nullable),
      `balance_change_sat`, and `confirmation` alongside the existing
      `txid` and `tx`.
      [#2060](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2060)
    - Retry Lightning receive claims before falling back to on-chain exit
      When claiming an incoming Lightning payment, transient failures (server
      restart, brief network blip) previously forced an immediate on-chain
      exit of the HTLC-recv VTXOs, losing the off-chain advantage of the
      receive. The claim is now retried up to `Config::lightning_receive_claim_retries`
      times with exponential backoff (2s up to 30s, ~60s total for the default
      budget of 5), exiting on-chain only if the budget is exhausted. The
      server's claim is idempotent and the preimage is already revealed at
      this point, so retrying is safe.
      [#2061](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2061)
    - Attach custom metadata to wallet history entries
      Developers integrating bark can now annotate movements after the fact —
      attaching refund references, customer or order IDs, internal notes, or
      any other JSON — without maintaining a parallel store keyed by movement
      ID. Exposed as `Wallet::update_history_metadata` and
      `POST /api/v1/history/{id}/metadata`, which take a JSON merge patch:
      keys set to `null` are removed, other values are merged recursively
      into the existing metadata. The history listing also moves to
      `GET /api/v1/history`; the old `GET /api/v1/wallet/history` stays but
      is deprecated.
      [#2079](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2079)
        - **BREAKING:** `Movement.metadata` (and `bark_json::Movement.metadata`)
          are now `serde_json::Map<String, Value>` instead of
          `HashMap<String, Value>`. JSON wire format and persisted data are
          unchanged.

- `bip321`
    - Add `bip321` crate for BIP 321 bitcoin payment URI parsing and serialization
      Implements the `bitcoin:` URI scheme for encoding payment instructions in
      clickable links and QR codes. Supports the standard payment parameters
      (`lightning`, `lno`, `sp`, `pay`, `bc`/`tb`) as well as a pluggable
      `ExtensionHandler` trait for custom or wallet-specific parameters. Handles
      `req-` prefixed required parameters per the spec, rejecting URIs whose
      mandatory extensions are unrecognised.
      [#1921](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1921)

- `server`
    - Add lightning send finished mailbox notification
      The server now notifies bark clients via the mailbox when a lightning
      send payment completes (success or failure), allowing clients to
      promptly process the result without polling.
      [#1889](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1889)
    - Add `GetOffboardFeeRate` RPC endpoint
      The offboard fee rate is now available via a dedicated endpoint so clients
      can fetch it without re-requesting all of `ArkInfo`. The field in `ArkInfo`
      is marked deprecated but still populated for older clients.
      [#2029](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2029)
    - Validate VTXO policy block heights and deltas at gRPC and DB boundaries
      `ArkInfo` deltas (`vtxo_exit_delta`, `vtxo_expiry_delta`,
      `htlc_send_expiry_delta`, `htlc_expiry_delta`, `max_user_invoice_cltv_delta`)
      arriving from the wire are now range-checked against the policy maximum
      rather than only against `u16::MAX`. The `expiry_height` field on
      `BoardCosignRequest` is similarly range-checked at the rpcserver boundary.
      Vtxo rows loaded from postgres validate `exit_delta` and `expiry` on read.

      Fixed two latent panic vectors in `watchman/policy.rs` where adversarial
      `exit_delta` could overflow `u16` (`2 * exit_delta`) or `u32`
      (`confirmed_at + BlockHeight::from(2 * exit_delta)`); these now use
      `checked_*` and reference the policy bound in their `expect` messages.
      [#2046](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/2046)

# v0.1.4

- `bark`
  - `bark address` no longer requires a connection to the Ark server
    The server public key and mailbox public key are now persisted in the local
    database after the first connection, so address generation works fully offline.
    [#1868](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1868)
  - Let `bark-wallet` compile without a selected Ark RPC transport backend
    Type-sharing consumers can now depend on `bark-wallet` without implicitly
    selecting `native` or `wasm-web`, and server-backed wallet operations now
    return a clear error that points developers to `bark-wallet/native` or
    `bark-wallet/wasm-web` when no transport backend was compiled in.
    [#1872](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1872)
    - Mobile builds now reject `tls-native-roots` on both Android and iOS and
      direct users to `tls-webpki-roots` instead.
  - Support an optional description on Lightning receive invoices
    `bark lightning invoice` now accepts a `--description <TEXT>` flag that is
    embedded in the generated BOLT-11 invoice as its memo, giving senders
    context about what the payment is for.
    [#1950](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1950)
    - **BREAKING:** `Wallet::bolt11_invoice` now takes a second parameter
      `description: Option<String>`; pass `None` to preserve the previous
      behaviour.
  - Wallet now owns its daemon handle and stops it on drop
    The `DaemonHandle` is kept internal to the `Wallet`, so the background
    daemon is automatically stopped when the wallet is dropped. A new
    `Wallet::stop_daemon` method is also exposed for callers that want to
    shut it down explicitly.
    [#1971](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1971)
    - **BREAKING:** `Wallet::open` now returns `Arc<Wallet>` instead of
      `(Arc<Wallet>, DaemonHandle)`.
    - **BREAKING:** `Wallet::run_daemon` now returns `()` instead of
      `DaemonHandle`, and errors if a daemon is already running for the
      wallet.
  - Rename `Wallet::register_vtxos_with_server` to `register_vtxo_transactions_with_server`
    The wrapper sends signed transaction chains for already-known VTXOs to the
    server; the new name matches the renamed RPC and removes the suggestion that
    it creates or registers VTXOs.
    [#1972](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1972)
    - **BREAKING:** `Wallet::register_vtxos_with_server` renamed to `Wallet::register_vtxo_transactions_with_server`.
  - deprecate `Wallet::run_daemon` in favor of `Wallet::start_daemon`
    [#1974](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1974)
  - don't produce error when calling `Wallet::start_daemon` with deamon already running
    [#1974](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1974)

- `bark-json`
  - Stop `bark-json` from selecting wallet transport features by default
    JSON-only consumers can now use `bark-json` for shared Bark types without
    implicitly enabling `bark-wallet/native` or a TLS root strategy.
    [#1872](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1872)

- `bark-rest`
  - Make `bark-rest` opt into native wallet transport explicitly
    The REST server no longer relies on `bark-json` feature unification to pull in
    wallet RPC support, which makes its server-only runtime requirements clearer.
    [#1872](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1872)
  - Expose a websocket gateway for real-time wallet notifications
    Clients can request a short-lived ticket from
    `/api/v1/notifications/ws/ticket` and upgrade to a long-lived websocket
    connection at `/api/v1/notifications/ws` to receive `WalletNotification`
    messages as they are emitted by the wallet, avoiding the need to poll
    REST endpoints for updates.
    [#1929](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1929)
  - Accept an optional description when creating a Lightning invoice
    `POST /api/v1/lightning/receives/invoice` now accepts an optional
    `description` field in `LightningInvoiceRequest`, which is embedded in the
    generated BOLT-11 invoice as its memo.
    [#1950](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1950)

- `server-rpc`
  - Let `bark-server-rpc` build without selecting `tonic-native` or `tonic-web`
    Generated gRPC client types now remain available in transportless builds, and
    connection attempts fail early with a clear error telling developers to enable
    `bark-server-rpc/tonic-native` or `bark-server-rpc/tonic-web`.
    [#1872](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1872)
    - Mobile builds now reject `tls-native-roots` on both Android and iOS and
      direct users to `tls-webpki-roots` instead.
  - Add optional `description` field to `StartLightningReceiveRequest`
    Clients can now pass an invoice memo through the RPC, which the server
    forwards to CLN's hold plugin when generating the BOLT-11 invoice. The
    field is optional, so existing clients remain compatible.
    [#1950](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1950)
  - Rename `RegisterVtxos` RPC to `RegisterVtxoTransactions`
    The previous name implied the call created or registered VTXOs server-side,
    but it only attaches signed transaction chains to VTXOs that already exist.
    The new name reflects what the RPC actually persists. The old `RegisterVtxos`
    method path is kept as a deprecated alias that delegates to the new handler,
    so existing clients continue to work without changes; new clients should call
    `RegisterVtxoTransactions`. The request message is unchanged.
    [#1972](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1972)

# v0.1.3

- `ark-lib`
  - Fix BOLT12 invoice verification for offers identified only by blinded paths
    `check_signature` now uses the invoice's `signing_pubkey` directly instead of
    requiring `issuer_signing_pubkey`. `validate_issuance` now verifies the
    invoice signature and, for offers without `issuer_signing_pubkey`, checks that
    the invoice's `signing_pubkey` matches the offer's last blinded hop. This fixes
    issues paying offers from Phoenix wallet, since they don't have an explicit
    issuer signing pubkey
    [#18
  - deprecated `VtxoId::utxo` and replace with `VtxoId::to_point`
    [#1926](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1926)91](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1891)

- `bark`
  - add IndexedDB persistence adaptor
    [#1776](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1776)
  - add ability to cancel pending lightning receives
    Users can now cancel a pending inbound lightning payment via
    `Wallet::cancel_lightning_receive` or the `bark lightning receive cancel` CLI command.
    [#1824](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1824)
  - add support for private servers with access token
    [#1927](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1927)
    - add config field `server_access_token`
    - add create option `--access-token`
    - add support for setting `ark-access-token` HTTP header
  - produce errors on fee estimation requests for amounts that are not allowed
    [#1932](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1932)
  - add `watch` command to stream wallet notifications
    [#1809](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1809)

- `server`
  - Enforce maximum VTXO exit depth to prevent DDoS vector
    This prevents database bloat and mobile client strain caused by chained OOR
    transactions where many small payments cause exit depth to balloon unboundedly.
    [#1791](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1791)
    - Added `max_input_exit_depth` validation to all cosign request paths (OOR, lightning pay/receive/revocation)
    - Exposed `max_arkoor_depth` in `ArkInfo` RPC so clients can check limits
    - Added regression test verifying exit depth limits are enforced
  - Add gRPC endpoint to cancel a pending lightning receive
    The server now exposes `CancelLightningReceive` allowing clients to cancel
    an in-flight inbound lightning payment by payment hash.
    [#1824](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1824)

# v0.1.2

- `bark`
  - Rename `boards/` endpoint to `boards/pending`
    The boards endpoint now more accurately reflects that it returns pending
    boards, not all boards. The REST client has been regenerated accordingly.
    [#1753](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1753)
    - **BREAKING:** `GET /boards` is now `GET /boards/pending`
  - Add `Wallet::open_with_daemon` API to start the daemon when opening a wallet
    Allows starting the daemon at wallet open time, optionally with an onchain
    wallet. This simplifies the wallet setup flow by combining open and daemon
    start into a single call.
    [#1865](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1865)
    - **BREAKING:** `Wallet::run_daemon` now takes `Option<Arc<RwLock<dyn DaemonizableOnchainWallet>>>` instead of `Arc<RwLock<dyn DaemonizableOnchainWallet>>`
    - **BREAKING:** `Wallet::run_daemon` is no longer async
  - Fix mailbox subscription loop not responding to shutdown signal
    The mailbox message processing loop now properly listens for the daemon
    shutdown signal, preventing the daemon from hanging on shutdown.
    [#1865](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1865)
  - Add arkoor address validation error type
    `Wallet::validate_arkoor_address` now returns a typed `ArkoorAddressError`
    instead of an opaque `anyhow::Error`, making it possible for callers to
    distinguish between network mismatch, server mismatch, unsupported policy,
    and missing delivery mechanism.
    [#1893](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1893)
    - **BREAKING:** `Wallet::validate_arkoor_address` returns `Result<(), ArkoorAddressError>` instead of `anyhow::Result<()>`
    - Make `subscribe_process_mailbox_messages` public again
    [#1904](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1904)

- `server`
  - Remove deprecated `PostVtxosMailbox` RPC endpoint and `MailboxType` enum
    Cleans up deprecated mailbox API that was replaced by `PostArkoorMessage`.
    The `mailbox_type` field is no longer included in `MailboxMessage` responses.
    [#1885](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1885)
    - **BREAKING:** `PostVtxosMailbox` RPC endpoint removed
    - **BREAKING:** `MailboxType` protobuf enum removed
    - **BREAKING:** `mailbox_type` field removed from `MailboxMessage`
  - add `captaind undo-round` command to manually undo a failed round
    [#1900](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1900)
  - Fix missing mailbox notification for intra-ark lightning receives
    When sender and receiver were on the same server, the receiver never got a
    LightningReceive mailbox message, requiring manual sync to claim the payment.
    [#1907](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1907)

# v0.1.1

- `bark`
  - Remove `tls-native-roots` from `native` feature
    The `native` feature now only enables gRPC transport without forcing a TLS
    root certificate strategy. This fixes Android builds where `rustls-native-certs`
    hangs because Android doesn't expose its certificate store via filesystem paths.
    Mobile consumers should use `native` + `tls-webpki-roots` with `default-features = false`.
    [#1870](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1870)
  - update the default bark config values for mainnet
    [#1871](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1871)

- `server`
  - correctly limit routing fees for lightning payments
    - add a `ln_max_fee_ppm` config to limit max fraction of fees that can go to routing
    [#1875](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1875)
  - `invoice_recheck_delay` config to `cln_xpay_timeout`
    [#1877](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1877)


- `server-rpc`
  - Return an error when HTTPS is used without TLS roots configured
    Previously, connecting to an HTTPS endpoint without `tls-native-roots` or
    `tls-webpki-roots` enabled would silently hang. Now it returns a clear error
    indicating that TLS roots are missing and HTTPS is unsupported.
    [#1870](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1870)

# v0.1.0

- `bark`
  - Add mailbox identifier to round participation.
    Round participation now includes a mailbox identifier. The server notifies
    the mailbox when non-interactive round participation completes via the new
    `RoundParticipationCompleted` message type.
    [#1613](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1613)
  - Add fee estimation endpoints to barkd REST API
    Integrators can now estimate fees before executing transactions via six new
    `/api/v1/fees/` endpoints: board, send-onchain, offboard-all, lightning pay,
    lightning receive, and on-chain fee rates. Each returns gross/net amounts and
    the fee breakdown so users can preview costs up front.
    [#1787](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1787)
  - Lightning receive notifications via mailbox
    Bark now receives a notification through the mailbox when a lightning
    payment arrives, prompting it to come online and claim. This replaces
    the dedicated lightning-receive polling task, resulting in faster
    payment detection.
    [#1792](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1792)
  - Add encoded VTXO endpoint to barkd REST API
    VTXOs can now be retrieved in hex-serialized form via `GET /vtxos/{id}/encoded`,
    making it easy to export and import VTXOs between wallets. The import endpoint
    also returns the encoded form for round-trip convenience.
    [#1800](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1800)
  - Configurable daemon sync intervals
    Operators can now tune barkd sync frequency via `config.toml` or `BARK_`
    environment variables (`daemon_fast_sync_interval_secs`,
    `daemon_slow_sync_interval_secs`).
    [#1810](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1810)
  - Drop `mailbox_type` from gRPC protocol
    The mailbox type is now inferred from the key type rather than being explicitly specified.
    [#1825](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1825)
  - Process RoundVtxos mailbox messages to progress non-interactive round participations
    When bark receives a `RoundVtxos` mailbox notification from the server, it now
    automatically syncs pending rounds. This enables delegated/non-interactive round
    participations to be progressed via mailbox notifications.
    [#1845](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1845)

- `server`
  - Add mailbox support for non-interactive round participation.
    The `vtxo_mailbox` table is renamed to `mailbox` and extended with a
    `payment_hash` column. Round outputs now include a mailbox identifier,
    and the server posts `RoundParticipationCompleted` messages to notify
    clients when their non-interactive round participation completes.
    [#1613](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1613)
  - Extract HTLC preimages from on-chain VTXO spends
    When a user claims an HTLC VTXO on-chain (emergency exit), the server
    now extracts the preimage from the spending witness and settles the
    corresponding CLN hold invoice automatically.
    [#1706](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1706)
  - Add `htlc_settlement_poll_interval` config option
    Controls how often the settler polls for cross-process HTLC settlements
    (e.g. preimages written by watchmand). Defaults to 60s.
    [#1706](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1706)
  - Add unit tests for all server database queries
    Every database query in the server's database module now has a dedicated
    unit test in `testing/tests/server/postgres.rs`. This catches SQL mistakes
    early, before integration tests, and ensures query correctness is verified
    at the level of individual database operations.
    [#1755](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1755)
  - Push lightning receive notifications to client mailboxes
    The server now notifies clients via the mailbox when a lightning
    payment arrives, enabling them to come online and claim without
    polling.
    [#1792](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1792)
  - Drop `mailbox_type` from gRPC protocol
    The mailbox type is now inferred from the key type rather than being explicitly specified.
    [#1825](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1825)
  - Make arkoor ownership attestation mandatory
    The attestation field on arkoor and lightning send cosign requests is now required.
    It was previously left optional for backward compatibility.
    [#1834](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1834)
    - **BREAKING:** `ArkoorCosignRequest.attestation` is no longer optional
    - Remove deprecated `PaymentStatus` enum and `LightningPaymentResult` message from gRPC
  - Send payment hashes in RoundVtxos mailbox messages
    When notifying clients about completed round participations, the server sends
    payment hashes (unlock hashes) so clients can sync the relevant rounds.
    [#1845](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1845)

- `server-rpc`
  - Add `RoundVtxosMessage` with `payment_hashes` field for round notifications
    The mailbox message for round vtxo notifications sends payment hashes
    (unlock hashes) to notify clients that their round participations are ready.
    [#1845](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1845)

# v0.1.0-beta.9

- `ark-lib`
  - Add `MailboxType` enum
    Introduces a typed mailbox system to distinguish different kinds of mailbox
    entries (e.g., `ArkoorReceive`). This enables better organization and future
    extensibility of the mailbox protocol.
  - add a generic to the `Vtxo` type in order to support "bare" `Vtxo`s that do not contains
    the full genesis transaction chain, but purely output into
    [#1746](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1746)
  - rename all the `Challenge` types to `Attestation` and make the attestation the object
    [#1757](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1757)

- `bark`
  - Don't advance wallet key index when no change output is created
    When creating an arkoor transaction spending the full VTXO amount, no change output is
    needed. Previously the wallet would still derive and persist a new keypair, unnecessarily
    advancing the key index. The key index is now only advanced when a change VTXO is actually
    produced.
    [#1441](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1441)
  - Wait for offboard tx confirmations before marking movement successful
    Offboard movements now remain pending until the transaction confirms on-chain,
    allowing recovery if the transaction fails to confirm.
    [#1618](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1618)
  - Log warning when exiting only dust VTXOs

    `exit --all` now logs a warning instead of silently succeeding when all
    VTXOs are below the dust limit. Suggests consolidating funds to meet
    the dust limit.

  - WASM and browser support for bark
    The bark wallet library now compiles to `wasm32-unknown-unknown`, enabling
    browser-based Ark wallets. Includes gRPC-web transport via the `tonic-web`
    feature flag, web-compatible async traits, and `spawn_local` on wasm targets.
    [#1709](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1709)
    - **BREAKING:** `sqlite` is no longer a default feature; enable it explicitly
    - **BREAKING:** `onchain_bdk` feature renamed to `onchain-bdk`
  - Add SOCKS5 proxy support for Tor connectivity
    New `socks5-proxy` feature allows routing traffic through a SOCKS5 proxy
    (e.g. Tor), configured via the `socks5-proxy` config option. Local addresses
    automatically bypass the proxy.
    [#1720](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1720)
  - Prove VTXO ownership on arkoor cosign requests
    Arkoor cosign requests now include a signed attestation, preventing
    a malicious user from locking someone else's VTXOs.
    [#1735](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1735)
  - Silence noisy log when should-refresh VTXOs can't cover fees
    When VTXOs in the "should refresh" zone were too small to produce an
    output above the dust limit after fees, a warning was logged on every
    refresh attempt. This is a normal condition, not an error. The message
    is now only emitted at trace level.
    [#1739](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1739)
  - Silence noisy log when invoice is open but not yet paid
    When a lightning invoice was open and the sender had not yet initiated
    the payment, the background daemon logged a warning every second while
    polling. This is expected behaviour, so the message is now only emitted
    at trace level.
    [#1747](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1747)
  - Fix typo in `bark-ffi` repository URL in README
    [#1763](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1763)
  - Return claimed lightning receives from `try_claim_all_lightning_receives`
    The claim-all API now returns the list of successfully claimed receives
    instead of `()`, making it easier for callers to act on claimed payments.
    [#1773](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1773)
  - Add mailbox message subscription for real-time arkoor delivery
    Bark now subscribes to a server-side mailbox stream instead of polling,
    allowing incoming arkoors to be processed as soon as they arrive.
    [#1779](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1779)
  - Add `get_all` method to `StorageAdaptor` and refine query semantics
    `query` is renamed to `query_sorted` and now requires an explicit sort key
    range, making it clear that only sorted records are returned. A new `get_all`
    method retrieves all unordered records in a partition without requiring a
    sort key.
    [#1786](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1786)
    - **BREAKING:** `StorageAdaptor::query` renamed to `query_sorted`
    - **BREAKING:** `Query::new` now requires a range parameter; use `Query::new_full_range` for the previous default behavior
    - **BREAKING:** New required method `StorageAdaptor::get_all`
  - Fee estimation no longer errors when the wallet has no funds
    `estimate_lightning_send_fee` and `estimate_send_onchain` now return a
    worst-case estimate instead of failing when the wallet lacks sufficient VTXOs.
    This lets callers display fee information before the user has funded their
    wallet.
    [#1790](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1790)
  - Add movement lookup by payment method.
    All movements are now indexed per payment method. Users can look up
    all movements for a given payment method via `Wallet::history_by_payment_method()`.
    For the CLI, we added `bark address lookup --address <addr>` / `bark address lookup --index <n>`
    to lookup movements by arkoor address.
    [#1798](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1798)
  - add `Wallet::mailbox_identifier` and simplify mailbox related APIs
    [#1802](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1802)
  - Add `Wallet::subscribe_notifications` that returns a stream of `WalletNotification` objects:
    - Current variants are `MovementCreated` and `MovementUpdated` and they are emitted whenever
  	a new movement is added or an existing movement is updated.
    - Utility functions exist on the stream type to get a single movement stream or to filter
  	for specific movements.
    [#1793](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1793)
    + [#1807](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1807)



  - Replace permissive CORS with deny-all default in barkd
    Cross-origin requests are now denied unless explicitly allowed via `--allowed-origins`
    or `BARKD_ALLOWED_ORIGINS`.
    [#1808](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1808)
    - **BREAKING:** CORS is no longer permissive by default. Set `BARKD_ALLOWED_ORIGINS` to
      re-enable cross-origin access for specific origins.

- `bark-cli`

  * Fix `ln status` can't find payment hash for outgoing payments
    [PR #1466](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1466)
    - Split `ln status` into `ln pay status` (outgoing) and `ln receive status` (incoming)
    - Add `LightningSendInfo` struct to display outgoing payment status
    - Include `finished_at` field to detect when a payment has failed or succeeded
  - Add wallet deletion support to `barkd`

    `barkd` now stops background tasks and wipes the wallet directory
    when `DELETE /api/v1/wallet` is called.

    [#1663](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1663)
  - Add auth token management to barkd
    On first start, barkd auto-generates an auth token and prints it to
    stderr. Use `barkd secret refresh` to regenerate or set a custom token.
    [#1756](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1756)

- `bark-json`
  - Add `WalletExistsResponse`, `WalletDeleteResponse`, and `WalletDeleteRequest` types

    [#1663](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1663)
  - Add missing fee information for amount parameters
    API request type documentation now describes applicable fees and dust
    thresholds for each endpoint, helping integrators understand the true
    cost of operations before submitting them.

- `bark-rest`
  - Add `GET /api/v1/wallet` and `DELETE /api/v1/wallet` endpoints with fingerprint verification

    Allows clients to check wallet existence and delete wallet data
    via the REST API.

    [#1663](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1663)
  - Add token-based authentication middleware
    New `auth` module with `AuthToken` type and `guard_auth` middleware that
    protects all `/api/v1` routes. Tokens use a versioned wire format
    (base64url-encoded) and can be passed via `auth-token` or
    `Authorization: AuthToken <token>` headers.
    [#1756](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1756)
    - **BREAKING:** `RestServer::start` now requires an `AuthToken` parameter
  - Add missing fee information for amount parameters in OpenAPI spec
    Parameter descriptions in the OpenAPI schema and generated client docs
    now document applicable fees and dust thresholds for each endpoint.

- `bitcoin-ext`
  - Make bitcoin-ext compatible with wasm targets
    [#1709](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1709)
  - Add SOCKS5 proxy transport for bitcoind RPC
    New `rpc-socks5-proxy` feature enables routing bitcoind JSON-RPC calls through
    a SOCKS5 proxy, using `ureq` with its `socks-proxy` feature for the HTTP transport.
    [#1720](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1720)

- `server`
  - Store mailbox type in database
    Mailbox entries now include a type field, allowing the server to distinguish
    between different kinds of mailbox messages.
  - Add gRPC-web layer to the server
    Browser-based clients can now connect to the Ark server using gRPC-web
    transport, enabling web wallet implementations.
    [#1709](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1709)
  - Verify arkoor cosign attestations
    The server now verifies that each arkoor cosign request includes a valid
    attestation, rejecting requests where the caller cannot prove they
    own the input VTXO.
    [#1735](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1735)
  - Add gRPC-web layer to the server
    Browser-based clients can now connect to the Ark server using gRPC-web
    transport, enabling web wallet implementations.
    [#1749](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1749)

- `server-rpc`
  - Add `tonic-web` feature for gRPC-web transport
    Enables browser-based clients to connect to the Ark server via gRPC-web.
    The `tonic-native` feature (default) provides the existing HTTP/2 transport.
    [#1709](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1709)
  - Add SOCKS5 proxy support for server gRPC connection
    New `socks5-proxy` feature enables routing the gRPC connection to the Ark
    server through a SOCKS5 proxy, using `hyper-socks2` as the connector.
    [#1720](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1720)

# v0.1.0-beta.8

- `ark-lib`
  - Add FeeSchedule to ArkInfo struct.
    This contains details and methods to calculate fees for board, offboard, send-onchain, refresh, and lightning
    operations.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Move ArkInfo.offboard_fixed_fee_vb to FeeSchedule.offboard.fixed_additional_vb.
    This contains details and methods to calculate fees for board, offboard, send-onchain, refresh, and lightning
    operations.
  - Remove `VtxoDelivery::ServerBuiltin` variant
    Only `VtxoDelivery::ServerMailbox` delivery is now supported for addresses.
    **BREAKING**: Old addresses using builtin delivery are no longer valid.
    [#1502](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1502)
  - Add fee amount as a field on GenesisItem.
    The benefit of this is that it allows us bundling fees for board and arkoor operations into the VTXO itself. This is
    backwards compatible.
    [#1535](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1535)
  - Add BoardFundingError to BoardBuilder.
    When setting funding details for the BoardBuilder, it will return errors if the amount and fee values don't validate.
    [#1535](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1535)
  - Improve the ability for servers to track their vtxos when hosting a round
    [#1569](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1569)
    - Introduced `HarkLeafVtxoPolicy`
    - Added `spend_info` to show which vtxo is spent by which tx
    - Added `internal_vtxos` to give insight into ServerVtxos
    - Added `unsigned_leaf_txs` and `build_signed_node_txs`
  - prevent a malicious VTXO encoding from crashing the decoder
    [#1573](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1573)
  - update the encoding of `SignedVtxoTreeSpec` with backwards compatible decoding
    [#1573](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1573)
  - rename `Vtxo::is_fully_signed` to `has_all_witnesses`
    [#1596](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1596)
  - Add `into_vtxo()` method to `VtxoRef` trait that returns `Vtxo` by value
    Allows the trait to provide VTXOs either by reference (`vtxo_ref()`) or by value (`into_vtxo()`),
    reducing unnecessary clones in some contexts.
    [#1614](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1614)
    - **BREAKING:** `VtxoRef::vtxo()` became `VtxoRef::vtxo_ref()`
  - re-license under the MIT license
    [#1621](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1621)
  - make our HTLC-like clause lightning-agnostic
    [#1629](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1629)
  - simplify the hArk forfeit protocol
    - reduce to a single tx and signature
    - change the HarkForfeitBundle serialization
    [#1698](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1698)
  - add `ServerVtxoPolicy::HarkForfeit` and eq policy kind
    [#1698](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1698)

- `bark`
  - Exit boards which fail to register before expiration.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Configure bark to use the new FeeSchedule in ArkInfo.
    Fees will be applied to board, offboard, refresh and lightning operations.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Add fee estimation API for various operations.
    Allows developers to provide fee estimates and VTXO choices to users in advance.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Remove legacy arkoor mailbox sync
    The `sync_oors` method has been removed. Use `sync_mailbox` instead.
    [#1502](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1502)
  - Remove unused `check_recipient_exists` method from `BarkPersister` trait
    [#1530](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1530)
  - Fail when refreshing dust VTXOs before waiting for a round
    Validate VTXO amount before waiting for a round, giving immediate feedback instead of waiting ~30 seconds for rejection.
    [#1576](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1576)
  - `bark`: Disallow creating and paying 0 sat lightning invoices
    Prevents users from creating invoices for 0 sats and from paying invoices
    that resolve to 0 sats, which are not useful and could cause issues.
  - Movements for lightning sends and receives now include the preimage when known
    [#1579](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1579)
  - Reject dust VTXOs during exit initiation
    Validate VTXO amount before starting an exit to avoid delayed rejection
    during round processing.
    [#1580](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1580)
  - Fix mailbox checkpoint not advancing due to SQL syntax error
    [#1584](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1584)
  - reduce the default number of required confirmations for round txs to 2 (1 for signet)
    [#1586](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1586)
  - change CLI output for delegated round participations
    [#1588](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1588)
  - Run all maintenance tasks regardless of error
    Previously when you ran any maintenance method, and an error was produced, the maintenance would early-out so some
    steps such as the maintenance refresh never ran. This behavior has been changed so that errors will be logged but the
    methods will not early-out. If an error does occur then an `anyhow::Error` will still be returned, however the full
    maintenance procedure will be attempted.
    [#1592](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1592)
  - Progress exits when any maintenance method is called
    Previously the exit system would be synced but no TRUC packages would be produced or broadcast. Now, bark will attempt
    to progress each exit each time a maintenance method is called.
    [#1592](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1592)
  - Add ability to manually import VTXOs into the wallet
    Allows importing serialized VTXOs via `bark dev vtxo import` CLI command
    or the `/import-vtxo` REST endpoint. Useful for recovering VTXOs.
    [#1607](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1607)
  - Populate `received_on` field for arkoor receive movements
    Previously, the `received_on` field was always empty for arkoor receives. Now it contains the Ark address(es) the
    VTXOs were received on, aggregated by address with the total amount received on each.
    [#1610](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1610)
  - Persist server pubkey and detect if it changes
    The wallet now stores the server's public key on first connection and verifies it on subsequent
    connections. If the server pubkey changes unexpectedly, the wallet will refuse to interact with
    the server and suggest the user manually exit their VTXOs. This protects against accidentally
    connecting to a different or compromised server.
    [#1611](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1611)
  - Refactor wallet code to extract functionality into dedicated modules
    Board, lightning send, lightning receive, and round balance functions have been moved from
    the main `lib.rs` into their respective modules (`board.rs`, `lightning/pay.rs`,
    `lightning/receive.rs`, and `round.rs`), improving code organization and modularity.
    [#1612](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1612)
  - Optimize `build_refresh_participation` to reduce allocations and database reads
    [#1614](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1614)
    - `build_refresh_participation` now checks if `VtxoRef` items can optionally provide
      the `Vtxo` directly, avoiding redundant database lookups
    - Internal implementation reduces memory allocations by pre-allocating vectors
  - Add `RefreshStrategy::should_refresh_exclusive` and `RefreshStrategy::should_refresh_if_must`
    variants for more granular VTXO refresh filtering
    [#1614](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1614)
    - `should_refresh_exclusive`: matches VTXOs that _should_ refresh but excludes those that
      _must_ refresh
    - `should_refresh_if_must`: only matches VTXOs (both _must_ or _should_) if at least one
      VTXO meets the _must_ refresh criteria
  - Add dust VTXO detection to refresh criteria
    VTXOs with amounts below P2TR dust threshold are now flagged for refresh.
    [#1614](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1614)
  - re-license under the MIT license
    [#1621](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1621)
  - add `Wallet::mailbox_authorization` method to create a new authorization for your server mailbox
    [#1625](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1625)
  - Report round failures as errors in the CLI
    Previously, when a round failed (e.g. due to a borked VTXO), `participate_round`
    returned `Ok(RoundStatus::Failed)` which caused the CLI to exit silently with
    no error. Now round failures and cancellations are properly propagated as errors.
    [#1640](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1640)
  - Add `PidLock` for exclusive datadir access
    Prevents multiple processes from operating on the same datadir
    concurrently by writing a `LOCK` file at startup. Available
    behind the `pid_lock` feature flag.
    [#1651](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1651)
  - only have `bark --version` return version when built on version tag,
    otherwise return `DIRTY` (alongside the commit hash)
    [#1653](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1653)
  - rename all feerate fields in JSON outputs
    - new fields have `_sat_per_kvb` suffix and are expressed as such
    - old fields are deprecated but still present
    [#1654](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1654)
  - `htlc_vtxos` in `LightningReceive` is now always a `Vec` instead of `Option<Vec>`
    [#1669](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1669)
    - **BREAKING:** `LightningReceive.htlc_vtxos` changed from `Option<Vec<WalletVtxo>>` to `Vec<WalletVtxo>`
    - **BREAKING:** `htlc_vtxos` in CLI/REST JSON output is now `[]` instead of `null` when no VTXOs are present
  - Fix race condition when processing round states concurrently
    Round states are now locked in memory while being processed, preventing
    multiple tasks from operating on the same round state simultaneously.
    [#1671](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1671)
  - Loosen restrictions on lightning receive overpayment
    If the server overpays the client we should allow this instead of bailing.
    [#1685](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1685)
  - Warn on inconsistent fee accounting for failed Lightning payments
    Bark now logs a warning when revoked or exited failed Lightning payments do not net to a zero effective fee, making unexpected balance deltas visible.
    Pending Lightning send records are also validated during SQLite loading by using checked conversions for `amount_sats` and `fee_sats`.
    [#1686](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1686)

- `bark-rest`
  - Add FeeSchedule to ArkInfo response.
    The REST API now includes a complete fee schedule for all operations (board, offboard, refresh, lightning send/receive).
    Clients can use this to calculate and display fees to users before performing operations.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
    - **BREAKING:** `offboard_fixed_fee_vb` field removed from ArkInfo, moved to `fees.offboard.fixed_additional_vb`
    - New types: `FeeSchedule`, `BoardFees`, `OffboardFees`, `RefreshFees`, `LightningReceiveFees`, `LightningSendFees`, `PpmExpiryFeeEntry`
  - Fix OpenAPI spec and generated clients for address endpoints
    The response type for `/addresses/next` and `/addresses/{index}` was
    incorrectly annotated, causing the generated Rust client to error on
    deserialization.
    [#1660](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1660)
  - `htlc_vtxos` in `LightningReceiveInfo` is now always returned as a list
    REST API clients no longer need to handle a missing or nullable field.
    [#1669](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1669)
    - **BREAKING:** `htlc_vtxos` is now `[]` instead of `null` when no VTXOs are present

- `bitcoin-ext`
  - Add workaround for creating P2A CPFPs when fee anchors contain a non-zero value.
    Allows for exiting VTXOs when fees are stored in the fee anchor.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)

  - Fix BlockRef JSON serialization to output proper object format
    BlockRef fields are now serialized as a JSON object with `height` and `hash`
    fields instead of a concatenated string like `"502:hash"`.
    [#1598](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1598)
  - Fix untrusted UTXO detection for external deposits
    External deposits were incorrectly treated as trusted when BDK happened
    to know about the parent transaction. Now checks that each input actually
    spends a wallet-owned output.
    [#1692](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1692)
  - Add `TrustedBalance` struct and `WalletExt::trusted_balance()`
    Computes wallet balance using the recursive `is_trusted_utxo` check,
    categorizing funds as trusted or untrusted.
    [#1705](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1705)

- `captaind`
  - Disallow creating and paying 0 sat lightning invoices
    These are not useful and could cause issues.
  - Standardize config option naming to use `max_` prefix style
    Config options now follow a consistent naming pattern. The old names
    are still accepted as aliases for backward compatibility.
    [#1616](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1616)
  - Add `captaind rpc ban` commands to ban/unban/list vtxos
    Allows operators to temporarily ban vtxos by duration or block count.
    Banned vtxos cannot be used in OOR sends, rounds, offboards, or lightning.
    [#1733](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1733)

- `server`
  - Add vtxo banning: temporarily ban vtxos by block height
    Banned vtxos are rejected in all spending flows (OOR, rounds, offboards, lightning)
    with a descriptive error including the remaining ban duration. Bans are stored as
    `banned_until_height` on the vtxo table and expire automatically.
    [#1733](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1733)
  - Implement fees for board, offboard, refresh and lightning operations.
    Fees are configured via the config file and are communicated to clients using ArkInfo. Fees are validated on the
    server side and require clients also calculate the same fee values.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Move offboard_fixed_fee_vb to fees.fixed_additional_vb in the server config.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
  - Update the offboard fee based on network conditions.
    Data from the fee estimator is used to calculate the offboard fee which is communicated to clients via ArkInfo.
    [#1509](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1509)
  - Permit historical offboard fee rates when clients attempt to perform an offboard request.
    When receiving an offboard request the client provides the fee rate they used to calculate the fees for the offboard.
    The server will check if this is a valid fee rate by consulting the new fee estimator history. If it's valid the
    offboard will be honored at the given fee rate, if not it will be rejected as an error.
    [#1509](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1509)
  - Add a Watchman which sweeps coins and will publish forfeits
    [#1560](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1560)
  - Restore round event replay for new subscribers
    Clients subscribing to round events now receive the current Attempt event,
    allowing them to join rounds during the signup phase. This fixes a
    regression where clients waking from push notifications would miss the
    Attempt event. Empty rounds no longer replay stale events.
    [#1572](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1572)
  - Make `claim_lightning_receive` idempotent
    Bark can now retry a lightning receive claim if something goes wrong,
    avoiding a forced on-chain exit.
    [#1605](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1605)
  - re-license under the MIT license
    [#1621](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1621)
  - no longer schedule a round right after startup, but wait until the first round interval passes
    [#1643](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1643)
  - rename the forfeit wallet to watchman wallet (in admin RPC interface)
    [#1646](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1646)
  - Fix incorrect structured log for lightning receive
    [#1685](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1685)
  - simplify the hArk forfeit protocol
    - reduce to a single tx and signature
    - remove `signed_forfeit_claim_tx` column from round participation input table
    [#1698](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1698)
  - handle hArk forfeit txs in sweeper
    [#1698](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1698)
  - fix a bug where VTXOs weren't correctly locked during rounds
    [#1701](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1701)
  - Use our recursive trust model for all balance reporting
    BDK's built-in balance categories used a shallow trust heuristic that
    could misclassify unconfirmed UTXOs. The server now uses `is_trusted_utxo`
    everywhere: wallet sync, admin RPC, telemetry gauges, and the CPFP
    funds check.
    [#1705](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1705)

- `server-rpc`
  - Add FeeSchedule and related fee messages to protobuf schema.
    ArkInfo now includes a complete fee schedule for all operations.
    [#1500](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1500)
    - New messages: `FeeSchedule`, `BoardFees`, `OffboardFees`, `RefreshFees`, `LightningReceiveFees`, `LightningSendFees`, `PpmExpiryFeeEntry`
    - `ArkInfo.offboard_fixed_fee_vb` moved to `FeeSchedule.offboard.fixed_additional_vb`
  - Remove deprecated legacy mailbox gRPC methods
    Removed `PostArkoorPackageMailbox` and `EmptyArkoorMailbox` methods.
    Use the new mailbox service (`PostVtxosMailbox`, `ReadMailbox`, `SubscribeMailbox`) instead.
    [#1502](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1502)
  - Simplify `WalletStatus` balance fields to trusted/untrusted
    [#1705](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1705)
    - **BREAKING:** `trusted_pending_balance`, `untrusted_pending_balance`, and
      `confirmed_balance` replaced by `trusted_balance` and `untrusted_balance`

# v0.1.0-beta.7

- `ark-lib`
  - Refactor `GenesisItem::Arkoor` to remove embedded policy
    Removes the `Policy` from `GenesisItem::Arkoor` to allow adding new policies
    without introducing breaking changes to the protocol encoding.
    [#1396](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1396)
    - **BREAKING:** `ProtocolEncoding` for `GenesisItem` has changed
  - Split `VtxoPolicy` into user-facing and server-internal types
    [#1542](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1542)
  - Fix encoding for VTXOs with more than 256 genesis items
    [#1550](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1550)
    - **BREAKING:** `ProtocolEncoding` for genesis length fields has changed
  - Fix bug in signed tree encoding/decoding round-trip
    [#1551](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1551)
  - Remove old pre-hark encoding of `VtxoTreeSpec`
    [#1552](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1552)
    - **BREAKING:** Old pre-hark `VtxoTreeSpec` encoding is no longer supported
  - `BoardBuilder` gains functionality to track `ServerVtxo`s
    and provides methods to build internal unsigned VTXOs and transactions.
    [#1513](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1513)
    - `CosignedGenesis::signature` is now `Option<schnorr::Signature>` to support
      constructing unsigned VTXOs for validation purposes. Wire format unchanged:
      `None` encodes as an all-zeros 64-byte signature.
    - Add `Vtxo::validate_unsigned` method for validating VTXO structure without
      checking signatures
    - Allow empty genesis in VTXO validation for VTXOs directly anchored on-chain
    - Add `BoardBuilder` query methods: `exit_tx()`, `exit_txid()`,
      `build_internal_unsigned_vtxos()`, and `spend_info()`
    - Add encoding tests for `GenesisTransition` variants

- `bark`
  - Implement unified mailbox delivery
    Bark now uses a unified mailbox system for receiving VTXOs, providing more
    reliable delivery across different sources.
    [#1412](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1412)
    - **BREAKING:** Addresses now use mailbox addresses
  - Add environment variable support to Config
    Bark configuration values can now be set via environment variables.
    [#1558](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1558)
  - `Wallet::next_round_start_time` to ask server for next round start time
    [#1559](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1559)
  - Add delegated maintenance and refresh APIs to `Wallet`:
    - `maintenance_delegated`
    - `maintenance_with_onchain_delegated`
    - `maybe_schedule_maintenance_refresh_delegated`
    - `refresh_vtxos_delegated`
    - `join_next_round_delegated`
    These methods return immediately with a pending movement that can be tracked
    via `sync()` for completion status.
    [#1566](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1566)
  - Add `--delegated` flag to `maintain` and `refresh` commands
    Allows non-blocking maintenance and refresh operations that return immediately.
    Users can track progress by monitoring movement status via `history` command.
    [#1566](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1566)

- `server`
  - add NextRoundTime endpoint to expose next scheduled round start time
    [#1559](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1559)
  - Migrate lightning invoice monitoring from polling to TrackAll stream
    Improves reliability of invoice status tracking with automatic stream
    recovery and more accurate timeout handling using accepted timestamps.
    [#1453](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1453)
  - Notify sender promptly on intra-ark lightning payment cancellation
    [#1543](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1543)
  - Drop the `board` database table
    Board tracking is now handled through the virtual transaction tree.
    [#1513](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1513)
    - Migration V26 removes the table
    - Remove board-specific database methods and sweep logic

# v0.1.0-beta.6

- `ark-lib`
  - `tree::signed` module is refactored to add hArk protocol
    [PR #1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
      - for hArk details, see https://delvingbitcoin.org/t/evolving-the-ark-protocol-using-ctv-and-csfs/1602
      - all leaves now have an unlock hash attached
      - leaf txs are no longer signed during the interactive process
  - Add `BoardBuilder::new_from_vtxo` to reconstruct a board from a VTXO
    Validates server pubkey, funding txid, and vtxo id match expected values
    [#1472](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1472)
  - changes to arkoor builder to support dust VTXOs
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
      - add dust isolation to the checkpointed arkoor builder
      - remove the old non-checkpointed arkoor builder
      - rename all checkpointed arkoor builder types to remove checkpoint from name
      - add `ArkoorDestination` type to replace `VtxoRequest` in arkoor context
- `bark`
  - round protocol changed to hArk protocol
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - offboards and onchain payments temporarily disabled
    - new round VTXOs are now not immediatelly spendable after interactive round part finished
  - all BarkPersister API was made async, resulting in most of
    Bark's API becoming async too
    [#1485](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1485)
  - support sending and receiving dust VTXOs
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - use checkpointed arkoor for lightning send
    - use dust-isolation in lightning send revocation and lightning receive
  - Wallet::try_claim_all_lightning_receives behaviour changed to not bail on first error
    [#1516](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1516)
    - returns Ok(()) if at least one pending lightning receive is successfully claimed
    - returns Ok(()) if there are no pending lightning receives to claim
    - returns an error if all claims for pending receive fail to be claimed
  - re-enable send-to-onchain functionality
    [#1531](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1531)
    - `bark send-onchain` command now returns offboard txid
    - using offboard swaps, the offboard tx is broadcast instantly
  - re-enable the offboard and send-onchain REST endpoints
    [#1534](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1534)
  - return a struct with offboard txid from offboard CLIs
    [#1534](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1534)
  - Replace VtxoSeed by WalletSeed to allow deriving key dedicated to mailbox
    **BREAKING**: normal derivations were replaced by hardened ones. Any wallet created
    before that change won't load successfully anymore
    [#1452](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1452)
- `bark-rest`
  - round protocol changed to hArk protocol
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - offboards and onchain payments temporarily disabled
    - new round VTXOs are now not immediately spendable after interactive round part finished
    - round status response structure changed
  - offboards got enabled again
    [#1534](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1534)
    - offboards work again after temporary disability
    - return type for offboard_vtxos and offboard_all endpoint changed to
      simple TxId
- `bark-wallet`
  - round protocol changed to hArk protocol
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - offboards and onchain payments temporarily disabled
    - new round VTXOs are now not immediately spendable after interactive round part finished
  - Make VTXO storage and state transitions idempotent for crash recovery
    [#1528](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1528)
    - `store_vtxos` now succeeds without modification if VTXO already exists
    - `mark_vtxos_as_spent` now succeeds if VTXO is already spent
    - **BREAKING:** If you implement your own `BarkPersister`, you need to update 
      `store_vtxos` to be idempotent (no-op if VTXO already exists)
- `bictoin-ext`
  - Add `get_block_by_height`
    Allows fetching a block by its height from bitcoind.
    [#1471](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1471)
- `captaind`
  - Validate board server pubkey during registration
    Rejects boards signed with a different server pubkey, preventing potential double-spend attacks
    [#1472](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1472)
  - Add FeeEstimator module for dynamic fee rate estimation
    Replaces hardcoded fallback fee rates with a centralized FeeEstimator that
    queries bitcoind for current fee estimates. Provides three fee tiers:
    fast (1-block), regular (3-block), and slow (6-block) confirmation targets.
    Falls back to configurable rates when estimation fails.
    - Removed config options:
      - `round_tx_feerate`
      - `[vtxo_sweeper] sweep_tx_fallback_feerate`
      - `[forfeit_watcher] claim_fallback_feerate`
      - `[vtxopool] issue_tx_fallback_feerate`
    - Added `[fee_estimator]` config section with:
      - `update_interval`: Interval to update fee estimates from bitcoind
      - `fallback_fee_rate_fast`: Fallback feerate for fast confirmation (1 block target)
      - `fallback_fee_rate_regular`: Fallback feerate for regular confirmation (3 block target)
      - `fallback_fee_rate_slow`: Fallback feerate for slow confirmation (6 block target)
    [#1496](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1496)
- `server`
  - round protocol is changed to hArk protocol
    [PR #1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - for hArk details, see https://delvingbitcoin.org/t/evolving-the-ark-protocol-using-ctv-and-csfs/1602
    - new gRPC endpoints for non-interactive rounds:
      - `SubmitRoundParticipation`
      - `RoundParticipationStatus`
      - `RequestLeafVtxoCosign`
      - `RequestForfeitNonces`
      - `ForfeitVtxos`
    - gRPC `SubmitPayment` now returns an unlock_hash
    - config `round_forfeit_nonces_timeout` (duration) added
  - Introduce `SyncManager` and `BlockIndex`.
    These are utilities that can be used for block based sync.
    Replaced `TipFetcher` by `SyncManager`.
    Introduced the `sync_manager_block_poll_interval` config to
    specify how frequently `SyncManager` should poll sync.
    [#1471](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1471)
  - Rename `hodl` references to `hold` across configuration and code.
    Fixes inconsistent spelling of `hodl` vs `hold` in configuration, daemon logic, tests, and documentation, improving naming consistency and clarity.
    [#1478](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1478)
  - Remove deprecated `PostArkoorPackageMailbox` and gRPC methods.
    [#1499](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1499)
  - support dust VTXOs in arkoor and lightning
    [#1440](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1440)
    - adds max_arkoor_fanout config for maximum arkoor outputs
    - add validation of arkoor cosign requests
    - use checkpoints for lightning send
    - use dust-isolation in lightning send revocation and lightning receive
    - use the new dust-isolation builder for VTXOpool to allow dust change when needed
    - gRPC changes:
      - rename `CheckpointedCosignOor` -> `RequestArkoorCosign`
      - rename `CheckpointedPackageCosignRequest` -> `ArkoorPackageCosignRequest`
      - rename `CheckpointedPackageCosignResponse` -> `ArkoorPackageCosignResponse`
      - `RequestLightningPayHtlcCosign` now returns `ArkoorPackageCosignResponse`
      - `RequestLightningPayHtlcRevocation` now takes `ArkoorPackageCosignRequest`
      - `ClaimLightningReceiveRequest` now has a `ArkoorPackageCosignRequest`
      - use new `ArkoorDestination` instead of `VtxoRequest` for arkoor
      - remove deprecated old arkoor-related types
- `server-rpc`
  - removal of deprecated gRPC methods and fields
    [PR #1501](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1501)
    - remove deprecated `wait` field from `InitiateLightningPaymentRequest`
    - remove deprecated `start_lightning_payment`, `finish_lightning_payment`,
      and `revoke_lightning_payment` methods
    - removed deprecated `max_arkoor_depth` field from `ArkInfo` and reorder
      fields
- `testing`
  - Add comprehensive `test_register_board` integration test
    Tests confirmation requirements, idempotency, and server pubkey validation
    [#1472](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1472)
  - Add `Bitcoind::wait_for_blockheight()` helper method
    [#1472](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1472)
  - `generate_blocks()` now returns the new block height
    [#1472](https://gitlab.com/ark-bitcoin/bark/-/merge_requests/1472)

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
