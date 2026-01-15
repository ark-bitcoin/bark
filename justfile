# Find the target directory
CARGO_TARGET := `cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'`
JUSTFILE_DIR := justfile_directory()
export CAPTAIND_EXEC := CARGO_TARGET / "debug" / "captaind"
export BARK_EXEC := CARGO_TARGET / "debug" / "bark"

SERVER_SQL_SCHEMA_PATH := "server/schema.sql"
BARK_SQL_SCHEMA_PATH := "bark/schema.sql"
BARK_OPENAPI_SCHEMA_PATH := "bark-rest/openapi.json"
BARK_REST_CLIENT_DIR := "bark-rest-client"
BARK_REST_VERSION := `grep '^version = ' bark-rest/Cargo.toml | sed -E 's/^version = "([^"]+)"/\1/'`

precheck CHECK:
	bash contrib/prechecks.sh {{CHECK}}
prechecks:
	just precheck rust_no_spaces_for_indent
	just precheck rust_no_whitespace_on_empty_lines
	just precheck unused_server_logs
	just precheck conflicting_migration_scripts

check:
	cargo check --all --tests --examples

checks: prechecks check

check-commits:
	bash contrib/check-commits.sh

build:
	cargo build --workspace

build-codecov:
	RUSTFLAGS="-C instrument-coverage" LLVM_PROFILE_FILE="your-binary-%p-%m.profraw" cargo build --workspace

docker-pull:
	if [ -n "${LIGHTNINGD_DOCKER_IMAGE-""}" ]; then docker image inspect "$LIGHTNINGD_DOCKER_IMAGE" > /dev/null 2>&1 && echo "Image already exists locally." || (echo "Image not found locally. Pulling..." && docker pull "$LIGHTNINGD_DOCKER_IMAGE"); fi

alias unit := test-unit
test-unit TEST="":
	cargo test --workspace --exclude ark-testing {{TEST}}

test-unit-codecov TEST="":
	cargo llvm-cov --workspace --exclude ark-testing --no-report {{TEST}}

test-unit-all:
	cargo test --workspace --exclude ark-testing

test-unit-all-codecov:
	cargo llvm-cov --workspace --exclude ark-testing --no-report

test-integration TEST="": build docker-pull
	cargo test --package ark-testing {{TEST}}
alias int := test-integration

# run all integration tests without logging and without early failure.
test-integration-all: build docker-pull
	TEST_LOG=off cargo test --package ark-testing --no-fail-fast
alias int-all := test-integration-all

test-integration-codecov TEST="": build-codecov docker-pull
	cargo llvm-cov --package ark-testing --no-report {{TEST}}


test-integration-esplora TEST="": build docker-pull
	CHAIN_SOURCE=esplora just int "{{TEST}}"
alias int-esplora := test-integration-esplora

# run all integration tests without logging and without early failure.
test-integration-esplora-all: build docker-pull
	TEST_LOG=off CHAIN_SOURCE=esplora cargo test --package ark-testing --no-fail-fast
alias int-esplora-all := test-integration-esplora-all

test-integration-esplora-codecov TEST="": build-codecov docker-pull
	CHAIN_SOURCE=esplora cargo llvm-cov --package ark-testing --no-report {{TEST}}


test-integration-mempool TEST="": build docker-pull
	CHAIN_SOURCE=mempool just int "{{TEST}}"
alias int-mempool := test-integration-mempool

# run all integration tests without logging and without early failure.
test-integration-mempool-all: build docker-pull
	TEST_LOG=off CHAIN_SOURCE=mempool cargo test --package ark-testing --no-fail-fast
alias int-mempool-all := test-integration-mempool-all

test-integration-mempool-codecov TEST="": build-codecov docker-pull
	CHAIN_SOURCE=mempool cargo llvm-cov --package ark-testing --no-report {{TEST}}

test: test-unit test-integration test-integration-esplora test-integration-mempool

codecov-report:
	cargo llvm-cov report --html --output-dir "./target/debug/codecov/"

release-server:
	RUSTFLAGS="-C debuginfo=2" cargo build --release --locked \
		--manifest-path server/Cargo.toml --target x86_64-unknown-linux-gnu

release-bark-linux:
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark-cli/Cargo.toml
	cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark-cli/Cargo.toml
	cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark-cli/Cargo.toml

release-bark: release-bark-linux
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark-cli/Cargo.toml
	cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark-cli/Cargo.toml
	cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark-cli/Cargo.toml


RUSTDOCSDIR := justfile_directory() / "rustdocs"
# This is opinionated, but doesn't matter. Any page has full search.
DEFAULT_DOCS_PATH := "bark/struct.Wallet.html"

# Generate rustdoc documentation for all crates and dependencies
[unix]
rustdocs ARG="":
	mkdir -p {{RUSTDOCSDIR}}
	cargo doc --target-dir {{RUSTDOCSDIR}} --locked --all --lib --examples {{ARG}}
	echo "Open Rust docs at file://{{RUSTDOCSDIR}}/doc/{{DEFAULT_DOCS_PATH}}"

[windows]
rustdocs ARG="":
	set shell := ["cmd.exe"]
	# Repetitive because I'm currently unable to create a named variable
	# sed is converting C:\path\to\justfile_folder into /c/path/to/justfile_folder
	mkdir -p $(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	cargo doc --locked --all --lib --examples --keep-going {{ARG}} \
		--target-dir $(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	echo "Open Rust docs at file://$(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs/doc/{{DEFAULT_DOCS_PATH}}"

rustdocs-internal:
	@just rustdocs --document-private-items


# cleans most of our crates, doesn't clean grpc gens, they are sometimes slow to build
clean:
	cargo clean \
		-p ark-lib \
		-p ark-testing \
		-p bark-server \
		-p bark-server-log \
		-p bark-server-rpc \
		-p bark-bitcoin-ext \
		-p bark-wallet \
		-p bark-json \
		-p bark-rest \
		-p bark-cli

# run a single clippy lint
clippy LINT:
	cargo clippy -- -A clippy::all -W clippy::{{LINT}}


dump-server-sql-schema:
	cargo run --example dump-server-postgres-schema > {{SERVER_SQL_SCHEMA_PATH}}
	# Use sed to remove lines that are hard to reproduce across different systems
	sed '/^-- Dumped by .*$/d' {{SERVER_SQL_SCHEMA_PATH}} \
	  | sed '/^-- Dumped from .*$/d' \
	  | sed '/^\\restrict.*$/d' \
	  | sed '/^\\unrestrict.*$/d' > {{SERVER_SQL_SCHEMA_PATH}}.tmp && mv {{SERVER_SQL_SCHEMA_PATH}}.tmp {{SERVER_SQL_SCHEMA_PATH}}
	echo "bark-server SQL schema written to {{SERVER_SQL_SCHEMA_PATH}}"
	chmod 644 bark/schema.sql

dump-bark-sql-schema:
	cargo run --example dump-sqlite-schema > {{BARK_SQL_SCHEMA_PATH}}
	echo "bark SQL schema written to {{BARK_SQL_SCHEMA_PATH}}"
	chmod 644 bark/schema.sql

dump-bark-rest-openapi-schema:
	cargo run --package bark-rest --example dump_api_docs > {{BARK_OPENAPI_SCHEMA_PATH}}
	chmod 644 bark-rest/openapi.json

generate-bark-rest-client: dump-bark-rest-openapi-schema
	rm -rf {{BARK_REST_CLIENT_DIR}}
	openapi-generator-cli generate \
		-i {{BARK_OPENAPI_SCHEMA_PATH}} \
		-g rust \
		-o {{BARK_REST_CLIENT_DIR}} \
		--package-name bark-rest-client \
		--artifact-version "{{BARK_REST_VERSION}}" \
		--additional-properties packageVersion="{{BARK_REST_VERSION}}"
	cargo add --package bark-rest-client --path bark-json
	cargo add --package bark-rest-client --path bark-rest
	rm {{BARK_REST_CLIENT_DIR}}/src/models/*.rs
	cp bark-rest/helpers/models.rs {{BARK_REST_CLIENT_DIR}}/src/models/mod.rs

generate-static-files: dump-server-sql-schema dump-bark-sql-schema generate-bark-rest-client


