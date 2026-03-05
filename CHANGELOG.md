CHANGELOG
=========

For more elaborate changelogs, refer to our documentation:
https://docs.second.tech/changelog/changelog/

Below is a more concise summary for each version.

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

- `server`
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
