# Writing Tests

Best practices for writing tests in this codebase.

## Test at the Lowest Level

Prefer unit tests over integration tests. Unit tests are faster, more reliable, and easier to debug. Only use integration tests when you need to verify behavior across multiple components.

## Test Locations

### Unit Tests

Place unit tests in inline `#[cfg(test)]` modules at the bottom of source files:

```rust
// In src/mymodule.rs

pub fn my_function() -> u32 {
    42
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_my_function() {
        assert_eq!(my_function(), 42);
    }
}
```

### Integration Tests

Place integration tests in `testing/tests/`. Each file focuses on a specific component:
- `testing/tests/bark.rs` - Bark wallet tests
- `testing/tests/server.rs` - Server/captaind tests
- `testing/tests/exit.rs` - Exit flow tests
- etc.

## Naming Conventions

- Use `snake_case` for test function names
- Be descriptive: `test_bark_address_changes` not `test_address`
- Group related tests with a common prefix matching the test file

## Test Helpers

### Convenience Functions

The `ark_testing` crate provides helper functions:

```rust
use ark_testing::{btc, sat, signed_sat, secs, TestContext};

// Amount helpers
let one_btc = btc(1);           // Amount::from_btc(1)
let one_thousand_sats = sat(1000);  // Amount::from_sat(1000)
let negative = signed_sat(-500);    // SignedAmount::from_sat(-500)

// Duration helper
let timeout = secs(30);         // Duration::from_secs(30)
```

### TestContext

Use `TestContext` for integration tests. It manages test infrastructure:

```rust
#[tokio::test]
async fn my_integration_test() {
    let ctx = TestContext::new("category/test_name").await;
    let srv = ctx.new_captaind("server", None).await;
    let bark1 = ctx.new_bark("bark1", &srv).await;

    // ... test logic
}
```

## Async Testing

Use `#[tokio::test]` for async tests:

```rust
#[tokio::test]
async fn async_test() {
    let result = some_async_function().await;
    assert!(result.is_ok());
}
```

## Dummy/Mock Patterns

### Dummy Implementations

Create dummy trait implementations for compile-time checks in `lib/src/test_util/dummy.rs`:

```rust
lazy_static! {
    pub static ref DUMMY_USER_KEY: Keypair = Keypair::from_str(
        "76f78cc00278817fe65fd81cb962782d2625834d08b66edbf2cd60f6c520db63",
    ).unwrap();
}

pub struct DummyTestVtxoSpec {
    pub amount: Amount,
    pub expiry_height: BlockHeight,
    // ...
}

impl Default for DummyTestVtxoSpec {
    fn default() -> Self { /* ... */ }
}
```

### Fixture Patterns

Create helper functions like `dummy_*()` for test data:

```rust
fn dummy_vtxo() -> Vtxo {
    DummyTestVtxoSpec::default().build().1
}

fn dummy_transaction() -> Transaction {
    // ...
}
```

## Roundtrip Tests

For types with encoding, test that serialization roundtrips:

```rust
use ark::test_util::encoding_roundtrip;

#[test]
fn test_vtxo_encoding() {
    let vtxo = dummy_vtxo();
    encoding_roundtrip(&vtxo);
}
```

For JSON serialization:

```rust
use ark::test_util::json_roundtrip;

#[test]
fn test_config_json() {
    let config = Config::default();
    json_roundtrip(&config);
}
```
