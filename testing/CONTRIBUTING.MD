# CONTRIBUTING

When writing a test you should first identify what the object under
test is.

## Writing server tests

Write unit tests in the module itself. Prefer unit tests when possible.
Write integration tests in `testing/tests/server`

**Make grpc-calls explicitly**
- **Do**: Use `bark_sdk` for simple set-up like creating a board
- **Do**: Call grpc explicitly
- **Do**: For idempotency tests, call the same RPC twice and assert the retry result
- **Don't**: Use barkd or bark-cli. This adds complexity under tests
- **Don't**: Define a proxy. You can just call the object under test

**Write tests per topic**
Starting an integration test is expensive
- **Do**: Check if there is a similar test and add the behavior
- **Do**: Test multiple behaviors in a single test
- **Don't**: Write 5 new tests

## Writing bark, barkd and bark_sdk tests

The tests are structured as follows
- `testing/tests/bark_legacy/compat`
- `testing/tests/bark_legacy/non_compat`
- `testing/tests/barkd/compat`
- `testing/tests/barkd/non_compat`
- `testing/tests/bark_sdk`

**Don't use the bark/bark-legacy binary**
- **Don't**: Write new tests using the `bark/bark-legacy` binary

**Think about backward compatibility**
We explicitly test for compatibility of older clients
with the current server in CI. A test will swap the old
`barkd`, `bark`, `bark-cli` and `bark-legacy` binaries
to an older version and we will verify if the tests still run.
- **Do**: Run tests related to payments in compat mode
- **Don't**: Run exit tests in compat mode. These tests are slow
 and expensive and don't rely on the server.
