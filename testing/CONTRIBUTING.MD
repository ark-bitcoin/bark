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

