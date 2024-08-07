

test-unit:
	cargo test --workspace --exclude ark-testing

test-integration:
	cargo test --package ark-testing

test: test-unit test-integration
