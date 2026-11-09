# Writing quality tests

This guide explains how to write a good test.
A good test is easy to understand, asserts an actual behavior and is cheap to run.

## Test behavior, not implementation

A good test checks behavior and keeps passing when we change
the implementation.

The opposite is a change-detector test. It fails on every
change to the implementation, even one that keeps the behavior.
Its value is negative.

Avoid:
- Tests with heavy mocking
- Asserting exact log lines

```rust
// Bad: any edit to abs.rs breaks it, even one that returns the same values.
#[test]
fn abs_source_is_unchanged() {
	assert_eq!(include_str!("abs.rs"), "pub fn abs(i: i64) -> i64 { if i < 0 { -i } else { i } }\n");
}

// Good: checks what abs() returns.
#[test]
fn abs_returns_magnitude() {
	assert_eq!(abs(-3), 3);
}
```

Sources:
- [Change-Detector Tests Considered Harmful](https://testing.googleblog.com/2015/01/testing-on-toilet-change-detector-tests.html)
- [Test Behavior, Not Implementation](https://testing.googleblog.com/2013/08/testing-on-toilet-test-behavior-not.html)

## Avoid trivial tests

A test that repeats a constant adds maintenance and catches nothing.
Reading the value is easier.

```rust
#[test]
fn test_vtxo_lifetime() {
	assert_eq!(VTXO_LIFETIME_BLOCKS, 48);
}
```

## Test at the lowest level

Write tests at the lowest level possible.

Bad: a bitcoind and a captaind start to check one config rule.
Starting them is expensive and slows down CI.

```rust
#[tokio::test]
#[should_panic]
async fn captaind_refuses_zero_min_trusted_confs() {
	let ctx = TestContext::new("server/captaind_refuses_zero_min_trusted_confs").await;
	ctx.captaind("server").cfg(|cfg| cfg.min_trusted_confs = 0).create().await;
}
```

Good: unit test each rule on `Config::validate`.
See `mainnet_refuses_zero_htlc_expiry_delta` in `server/src/config.rs`.

```rust
#[test]
fn refuses_zero_min_trusted_confs() {
	let mut cfg = Config::load(DEFAULT_CAPTAIND_CONFIG_PATH).unwrap();
	cfg.bitcoind.cookie = Some(".cookie".into());
	cfg.min_trusted_confs = 0;
	cfg.validate().expect_err("zero min_trusted_confs");
}
```

Then one integration test checks that captaind calls `validate` at startup.

```rust
#[tokio::test]
async fn captaind_refuses_invalid_config() {
	let ctx = TestContext::new("server/captaind_refuses_invalid_config").await;
	ctx.captaind("server").cfg(|cfg| cfg.min_trusted_confs = 0)
		.try_create().await.expect_err("invalid config");
}
```

## Write tests that can be read top to bottom

Bad: We are asserting server behavior and want to know if we can safely
     call and endpoint twice. The test doesn't even show which endpoint
	 is problematic.

```rust
/// Sends every finish_offboard request twice, like a client that lost
/// the first response and retries.
#[derive(Clone)]
struct ReplayFinishOffboardProxy;

#[async_trait::async_trait]
impl captaind::proxy::ArkRpcProxy for ReplayFinishOffboardProxy {
	async fn finish_offboard(
		&self, upstream: &mut ArkClient, req: protos::FinishOffboardRequest,
	) -> Result<protos::FinishOffboardResponse, tonic::Status> {
		upstream.finish_offboard(req.clone()).await?;
		Ok(upstream.finish_offboard(req).await?.into_inner())
	}
}

#[tokio::test]
async fn finish_offboard_replays_for_identical_retry() {
	let ctx = TestContext::new("server/finish_offboard_replays_for_identical_retry").await;
	let srv = ctx.captaind("server").funded(btc(10)).create().await;
	let proxy = srv.start_proxy_no_mailbox(ReplayFinishOffboardProxy).await;
	let wallet = ctx.bark_sdk("bark", &proxy).boarded(sat(800_000)).create().await;

	let address = ctx.bitcoind().get_new_address();
	wallet.offboard_all(address).await.expect("offboard despite the retry");
}
```

Good: The goal of the test is to assert that every endpoint is idempotent
      We do this explicitly by calling every endpoint twice.

```rust
#[tokio::test]
async fn finish_offboard_replays_for_identical_retry() {
	let ctx = TestContext::new("server/finish_offboard_replays_for_identical_retry").await;
	// Every fee rate is 1 sat/vB, so the request can use a fixed fee.
	let srv = ctx.captaind("server").funded(btc(10)).cfg(|cfg| {
		cfg.fee_estimator.fallback_fee_rate_fast = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_regular = FeeRate::from_sat_per_vb_u32(1);
		cfg.fee_estimator.fallback_fee_rate_slow = FeeRate::from_sat_per_vb_u32(1);
	}).create().await;
	let wallet = ctx.bark_sdk("bark", &srv).boarded(sat(800_000)).create().await;
	let mut rpc = srv.get_public_rpc().await;

	// The wallet only provides the vtxo and its key; the test talks to the server itself.
	let vtxo_id = wallet.spendable_vtxos().await.unwrap()[0].id();
	let vtxo = wallet.get_full_vtxo(vtxo_id).await.unwrap();
	let key = wallet.get_vtxo_key(&vtxo).await.unwrap();

	// Offboard the 800_000 sat vtxo to a fresh address, paying 1_000 sat in fees.
	let req = OffboardRequest {
		script_pubkey: ctx.bitcoind().get_new_address().script_pubkey(),
		net_amount: sat(799_000),
		deduct_fees_from_gross_amount: true,
		fee_rate: FeeRate::from_sat_per_vb_u32(1),
	};

	let prepare = protos::PrepareOffboardRequest {
		offboard: Some((&req).into()),
		input_vtxo_ids: vec![vtxo_id.to_bytes().to_vec()],
		attestation: vec![OffboardRequestAttestation::new(&req, &[vtxo_id], &key).serialize()],
	};

	// A client that lost the first response sends the same prepare_offboard again.
	let prepared = rpc.prepare_offboard(prepare.clone()).await.unwrap().into_inner();
	let retry = rpc.prepare_offboard(prepare).await.unwrap().into_inner();
	// The retry gets the same unsigned offboard tx and forfeit nonces.
	assert_eq!(prepared, retry);

	// Sign the forfeits against the server's nonces.
	let offboard_tx = bitcoin::consensus::deserialize::<Transaction>(&prepared.offboard_tx).unwrap();
	let server_nonces = prepared.forfeit_cosign_nonces.iter()
		.map(|n| musig::PublicNonce::from_bytes(n).unwrap())
		.collect::<Vec<_>>();
	let sigs = OffboardForfeitContext::new(&[vtxo.clone()], &offboard_tx).unwrap()
		.user_sign_forfeits(&[key], &server_nonces).unwrap();
	let finish = protos::FinishOffboardRequest {
		offboard_txid: offboard_tx.compute_txid().to_byte_array().to_vec(),
		user_nonces: sigs.public_nonces.iter().map(|n| n.serialize().to_vec()).collect(),
		partial_signatures: sigs.partial_signatures.iter().map(|s| s.serialize().to_vec()).collect(),
	};

	// A client that lost the first response sends the same finish_offboard again.
	let first = rpc.finish_offboard(finish.clone()).await.unwrap().into_inner();
	let retry = rpc.finish_offboard(finish).await.unwrap().into_inner();
	// The retry gets the same signed offboard tx.
	assert_eq!(first, retry);
}
```

## Wait for events, not time

Avoid `tokio::time::sleep`. Wait for an event, or trigger the work yourself.
A sleep guesses how long the work takes. On a busy CI machine the guess is
too short and the test fails at random. Everywhere else it is too long and
the test is slow.

```rust
// Bad: hopes the next round has started after 5 seconds
tokio::time::sleep(Duration::from_secs(5)).await;

// Good: starts the round now
srv.trigger_round().await;

// Good: waits until the watchman has seen the new block
let tip = ctx.generate_blocks(1).await;
wm.wait_for_sync_height(tip).await;
```

## Writing doc-tests

The goal of a doc-test is to explain how a user is supposed
to use the functionality. A high-quality doc-test shows
how different components work together.

Example: `calc_ppm_expiry_fee` in `lib/src/fees.rs`.

```rust
let table = vec![
    PpmExpiryFeeEntry { expiry_blocks_threshold: 10, ppm: PpmFeeRate::ONE_PERCENT },
    PpmExpiryFeeEntry { expiry_blocks_threshold: 20, ppm: PpmFeeRate(50_000) }, // 5%
];
let vtxos = vec![
    VtxoFeeInfo { amount: Amount::from_sat(5_000), expiry_blocks: 2 },
    VtxoFeeInfo { amount: Amount::from_sat(3_000), expiry_blocks: 12 },
    VtxoFeeInfo { amount: Amount::from_sat(7_000), expiry_blocks: 22 },
];
let fee = calc_ppm_expiry_fee(Some(Amount::from_sat(15_000)), &table, vtxos);
assert_eq!(fee, Some(Amount::from_sat(380))); // 5,000 * 0% + 3,000 * 1% + 7,000 * 5%
```

## Write unit tests

Unit tests are cheap and fast. They add little time to CI.
They also push you to write composable code.

## Naming tests

A good test clarifies what is being tested.

## How tests are structured
