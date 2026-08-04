# Integration test harness

## Which bark to drive

Put new wallet tests in [tests/bark_sdk](tests/bark_sdk). These tests drive
the in-process wallet SDK.

When a test must drive a CLI binary, use `bark-cli`, the thin REST client
that drives barkd. Use the [`BarkClient`](src/bark_client.rs) wrapper. It
resolves the binary through `BARK_CLIENT_EXEC`. See
[tests/bark_client/lifecycle.rs](tests/bark_client/lifecycle.rs) for
examples.

Do not write new code against `bark-legacy`, the in-process CLI behind
the [`Bark`](src/bark.rs) wrapper and `BARK_EXEC`. It exists to keep the
test coverage and avoid regressions.
