# Find the target directory
CARGO_TARGET := `cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'`
JUSTFILE_DIR := justfile_directory()
export CAPTAIND_EXEC := env("CAPTAIND_EXEC", CARGO_TARGET / "debug" / "captaind")
export BARK_EXEC := env("BARK_EXEC", CARGO_TARGET / "debug" / "bark")
export BARKD_EXEC := env("BARKD_EXEC", CARGO_TARGET / "debug" / "barkd")
export BITCOIND_SNAPSHOT_DIR := JUSTFILE_DIR / "test" / "_bitcoind_snapshot"

NEXTEST_PROFILE := env("NEXTEST_PROFILE", "default")

SERVER_SQL_SCHEMA_PATH := "server/schema.sql"
BARK_SQL_SCHEMA_PATH := "bark/schema.sql"
BARK_OPENAPI_SCHEMA_PATH := "bark-rest/openapi.json"
BARK_REST_CLIENT_DIR := "bark-rest-client"
BARK_REST_VERSION := `grep '^version = ' bark-rest/Cargo.toml | sed -E 's/^version = "([^"]+)"/\1/'`

EXAMPLES_DIR := env("EXAMPLES_DIR", CARGO_TARGET / "debug" / "examples")

precheck CHECK:
	bash contrib/prechecks.sh {{CHECK}}
prechecks:
	just precheck rust_no_spaces_for_indent
	just precheck rust_no_whitespace_on_empty_lines
	just precheck unused_server_logs
	just precheck conflicting_migration_scripts

check:
	cargo version
	cargo check --all --tests --examples

checks: prechecks check

check-commits:
	bash contrib/check-commits.sh

build:
	cargo version
	cargo build --workspace

build-ci:
	cargo version
	cargo build --profile ci --workspace --bins --examples

build-unit-tests-ci:
	cargo nextest archive --cargo-profile ci --workspace --exclude ark-testing --archive-file {{CARGO_TARGET}}/ci/unit-tests.tar.zst --zstd-level 19

build-integration-tests-ci:
	cargo nextest archive --cargo-profile ci --package ark-testing --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst --zstd-level 19

build-bins:
	cargo build --workspace --bins

build-examples:
	cargo build --workspace --examples

ensure-build-bins:
	#!/usr/bin/env bash
	set -euo pipefail
	if [ -z "${ASSUME_BUILT:-}" ]; then
		just build-bins
	else
		echo "ASSUME_BUILT is set, skipping build"
	fi

ensure-build-examples:
	#!/usr/bin/env bash
	set -euo pipefail
	if [ -z "${ASSUME_BUILT:-}" ]; then
		just build-examples
	else
		echo "ASSUME_BUILT is set, skipping build"
	fi

build-codecov:
	#!/usr/bin/env bash
	set -euo pipefail
	source <(cargo llvm-cov show-env --export-prefix)
	cargo llvm-cov clean --workspace
	cargo build --workspace

docker-pull:
	if [ -n "${LIGHTNINGD_DOCKER_IMAGE-""}" ]; then docker image inspect "$LIGHTNINGD_DOCKER_IMAGE" > /dev/null 2>&1 && echo "Image already exists locally." || (echo "Image not found locally. Pulling..." && docker pull "$LIGHTNINGD_DOCKER_IMAGE"); fi

test-unit TEST="":
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --workspace --exclude ark-testing {{TEST}}
alias unit := test-unit

test-unit-codecov TEST="":
	cargo llvm-cov nextest --profile {{NEXTEST_PROFILE}} --workspace --exclude ark-testing --no-report {{TEST}}

test-integration TEST="": ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing {{TEST}}
alias int := test-integration

# run integration tests for bark and barkd test files only
test-integration-bark: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing --test bark --test barkd
alias int-bark := test-integration-bark

# run integration tests for core and server test files only
test-integration-core: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing --test core --test server
alias int-core := test-integration-core

test-integration-prebuilt TEST="": docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst {{TEST}}

test-integration-bark-prebuilt: docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst -E 'binary(bark) + binary(barkd)'

test-integration-core-prebuilt: docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst -E 'binary(core) + binary(server)'

test-integration-codecov TEST="": docker-pull
	#!/usr/bin/env bash
	set -euo pipefail
	source <(cargo llvm-cov show-env --export-prefix)
	cargo nextest run --profile {{NEXTEST_PROFILE}} --package ark-testing {{TEST}}
alias int-cov := test-integration-codecov

test-integration-esplora TEST="": ensure-build-bins docker-pull
	CHAIN_SOURCE=esplora just int "{{TEST}}"
alias int-esplora := test-integration-esplora

test-integration-esplora-codecov TEST="": docker-pull
	#!/usr/bin/env bash
	set -euo pipefail
	source <(cargo llvm-cov show-env --export-prefix)
	CHAIN_SOURCE=esplora cargo nextest run --profile {{NEXTEST_PROFILE}} --package ark-testing {{TEST}}

test-integration-mempool TEST="": ensure-build-bins docker-pull
	CHAIN_SOURCE=mempool just int "{{TEST}}"
alias int-mempool := test-integration-mempool

test-integration-mempool-codecov TEST="": docker-pull
	#!/usr/bin/env bash
	set -euo pipefail
	source <(cargo llvm-cov show-env --export-prefix)
	CHAIN_SOURCE=mempool cargo nextest run --profile {{NEXTEST_PROFILE}} --package ark-testing {{TEST}}

test-integration-all-codecov: docker-pull
	just test-integration-codecov
	just test-integration-mempool-codecov
alias int-all-cov := test-integration-all-codecov

test-all-codecov:
	just test-unit-codecov
	just test-integration-all-codecov
test: test-unit test-integration test-integration-esplora test-integration-mempool

codecov-report:
	cargo llvm-cov report --html --output-dir "./target/debug/codecov/"

release-server:
	RUSTFLAGS="-C debuginfo=2" cargo build --release --locked \
		--manifest-path server/Cargo.toml --target x86_64-unknown-linux-gnu

release-bark-linux:
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark-cli/Cargo.toml
	RUSTC_WRAPPER= cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark-cli/Cargo.toml
	RUSTC_WRAPPER= cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark-cli/Cargo.toml

release-bark: release-bark-linux
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark-cli/Cargo.toml
	RUSTC_WRAPPER= cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark-cli/Cargo.toml
	RUSTC_WRAPPER= cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark-cli/Cargo.toml


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


dump-server-sql-schema: ensure-build-examples
	{{EXAMPLES_DIR}}/dump-server-postgres-schema > {{SERVER_SQL_SCHEMA_PATH}}
	# Use sed to remove lines that are hard to reproduce across different systems
	sed '/^-- Dumped by .*$/d' {{SERVER_SQL_SCHEMA_PATH}} \
	  | sed '/^-- Dumped from .*$/d' \
	  | sed '/^\\restrict.*$/d' \
	  | sed '/^\\unrestrict.*$/d' > {{SERVER_SQL_SCHEMA_PATH}}.tmp && mv {{SERVER_SQL_SCHEMA_PATH}}.tmp {{SERVER_SQL_SCHEMA_PATH}}
	echo "bark-server SQL schema written to {{SERVER_SQL_SCHEMA_PATH}}"
	chmod 644 bark/schema.sql

dump-bark-sql-schema: ensure-build-examples
	{{EXAMPLES_DIR}}/dump-sqlite-schema > {{BARK_SQL_SCHEMA_PATH}}
	echo "bark SQL schema written to {{BARK_SQL_SCHEMA_PATH}}"
	chmod 644 bark/schema.sql

dump-bark-rest-openapi-schema: ensure-build-examples
	{{EXAMPLES_DIR}}/dump_api_docs > {{BARK_OPENAPI_SCHEMA_PATH}}
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
