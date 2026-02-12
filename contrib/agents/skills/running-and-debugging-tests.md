# Running and Debugging Tests

How to run, debug, and investigate test failures in this codebase.

## CRITICAL: Integration Tests Require `just int`

**Never run integration tests directly with `cargo test`!**

Integration tests require environment variables `CAPTAIND_EXEC` and `BARK_EXEC` to point to the built binaries. The `just int` command sets these automatically.

Running `cargo test --package ark-testing` directly will fail because the test framework won't be able to find the executables.

## Pre-Checks

Before committing, always run:

```bash
just checks
```

This runs:
- `just prechecks` - Code style checks (no spaces for indent, no whitespace on empty lines, etc.)
- `cargo check --all --tests --examples` - Type checking

## Unit Tests

Run all unit tests:

```bash
just unit
```

Run a specific unit test:

```bash
just unit test_name
```

Unit tests run against all workspace crates except `ark-testing`.

## Integration Tests

### Default (bitcoind)

Run all integration tests:

```bash
just int
```

Run a specific integration test:

```bash
just int test_name
```

### Chain Source Variants

Run with Esplora backend:

```bash
just int-esplora
just int-esplora test_name
```

Run with mempool.space backend:

```bash
just int-mempool
just int-mempool test_name
```

### All Tests Without Fail-Fast

Run all integration tests without stopping on first failure:

```bash
just int-all
just int-esplora-all
just int-mempool-all
```

This is useful for CI or when you want to see all failures at once. Test logging is disabled in this mode.

## Running Specific Tests

Pass the test name as an argument to filter:

```bash
# Unit tests
just unit bark_version

# Integration tests
just int bark_version
```

The test name is passed to `cargo test`, so you can use partial matches.

## Build Before Testing

Integration tests automatically build before running (`just build` is a dependency). Unit tests do not require a build step.

## Test Logging

Integration tests emit logs by default. To disable:

```bash
TEST_LOG=off just int
```

The `int-all` variants automatically disable logging.

## Test Artifacts

Integration tests create artifacts in `test/<test_path>/` containing:
- Server logs (`server/stdout.log`, `server/stderr.log`)
- Bark client logs (`bark/debug.log`, `bark/commands.log`)
- Database files (SQLite and PostgreSQL)
- Configuration files

### Keeping Artifacts

By default, test artifacts are:
- **Kept** for failed tests
- **Deleted** for passing tests

To keep artifacts for all tests (including passing ones):

```bash
KEEP_ALL_TEST_DATA=1 just int test_name
```

To use a custom test directory:

```bash
TEST_DIRECTORY=/tmp/my-test-dir just int test_name
```

## Debugging Test Failures

When a test fails, don't guess — investigate the artifacts. The nix flake
provides all the tooling you need (`sqlite3`, `psql`, etc.).

### 1. Read the logs

Start with the logs to understand the sequence of events:
- `test/<test_path>/server/stdout.log` - Server logs with round events
- `test/<test_path>/bark/debug.log` - Client-side logs
- `test/<test_path>/bark/commands.log` - CLI commands executed

### 2. Query the databases

Logs don't always tell the full story. Check the actual state in the databases.
The nix flake provides `sqlite3`, `psql`, and `postgres`.

**SQLite** (bark client databases):

```bash
sqlite3 test/<test_path>/bark/db.sqlite3 ".tables"
sqlite3 test/<test_path>/bark/db.sqlite3 "SELECT * FROM <table>;"
```

**PostgreSQL** (server database):

The test-managed PostgreSQL is shut down when the test finishes, but the data
directory survives in `test/<test_path>/postgres/pg_data/`. Restart it:

```bash
postgres -D test/<test_path>/postgres/pg_data -p 5555 &
psql -h /tmp/ark-testing-postgres-locks -p 5555 -U postgres -c "\l"
psql -h /tmp/ark-testing-postgres-locks -p 5555 -U postgres -d <dbname> -c "SELECT * FROM <table>;"
```

Stop it when done: `pg_ctl -D test/<test_path>/postgres/pg_data stop`

Look at actual database state to understand what the system did vs what you
expected. This is often more reliable than parsing logs.

### 3. Correlate across components

Piece together the timeline: what did the server do, what did bark see, and
where did they diverge? The database state on both sides is the ground truth.
