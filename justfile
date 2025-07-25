# Find the target directory
CARGO_TARGET := `cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'`
JUSTFILE_DIR := justfile_directory()
export ASPD_EXEC := CARGO_TARGET / "debug" / "aspd"
export BARK_EXEC := CARGO_TARGET / "debug" / "bark"

DEFAULT_ASPD_CONFIG_PATH := "aspd/config.default.toml"
BARK_SQL_SCHEMA_PATH := "bark/schema.sql"
ASPD_SQL_SCHEMA_PATH := "aspd/schema.sql"

precheck CHECK:
	bash contrib/prechecks.sh {{CHECK}}
prechecks:
	just precheck rust_no_spaces_for_indent
	just precheck rust_no_whitespace_on_empty_lines
	just precheck unused_aspd_logs

check:
	cargo check --all --tests

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
	RUST_LOG=0 cargo test --package ark-testing --no-fail-fast
alias int-all := test-integration-all

test-integration-codecov TEST="": build-codecov docker-pull
	cargo llvm-cov --package ark-testing --no-report {{TEST}}


test-integration-esplora TEST="": build docker-pull
	CHAIN_SOURCE=esplora-electrs just int "{{TEST}}"
alias int-esplora := test-integration-esplora

# run all integration tests without logging and without early failure.
test-integration-esplora-all: build docker-pull
	RUST_LOG=0 CHAIN_SOURCE=esplora-electrs cargo test --package ark-testing --no-fail-fast
alias int-esplora-all := test-integration-esplora-all

test-integration-esplora-codecov TEST="": build-codecov docker-pull
	CHAIN_SOURCE=esplora-electrs cargo llvm-cov --package ark-testing --no-report {{TEST}}


test-integration-mempool TEST="": build docker-pull
	CHAIN_SOURCE=mempool-electrs just int "{{TEST}}"
alias int-mempool := test-integration-mempool

# run all integration tests without logging and without early failure.
test-integration-mempool-all: build docker-pull
	RUST_LOG=0 CHAIN_SOURCE=mempool-electrs cargo test --package ark-testing --no-fail-fast
alias int-mempool-all := test-integration-mempool-all

test-integration-mempool-codecov TEST="": build-codecov docker-pull
	CHAIN_SOURCE=mempool-electrs cargo llvm-cov --package ark-testing --no-report {{TEST}}

test: test-unit test-integration test-integration-esplora test-integration-mempool

codecov-report:
	cargo llvm-cov report --html --output-dir "./target/debug/codecov/"

release-aspd:
	RUSTFLAGS="-C debuginfo=2" cargo build --release --target x86_64-unknown-linux-gnu --locked --manifest-path aspd/Cargo.toml

release-bark:
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark/Cargo.toml
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark/Cargo.toml
	cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark/Cargo.toml
	cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark/Cargo.toml
	cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark/Cargo.toml
	cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark/Cargo.toml


RUSTDOCSDIR := justfile_directory() / "rustdocs"
# This is opinionated, but doesn't matter. Any page has full search.
DEFAULT_DOCS_PATH := "bark/struct.Wallet.html"

# Generate rustdoc documentation for all crates and dependencies
[unix]
rustdocs:
	mkdir -p {{RUSTDOCSDIR}}
	cargo doc --target-dir {{RUSTDOCSDIR}} --locked --all --lib --examples --document-private-items
	echo "Open Rust docs at file://{{RUSTDOCSDIR}}/doc/{{DEFAULT_DOCS_PATH}}"

[windows]
rustdocs:
	set shell := ["cmd.exe"]
	# Repetitive because I'm currently unable to create a named variable
	# sed is converting C:\path\to\justfile_folder into /c/path/to/justfile_folder
	mkdir -p $(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	cargo doc --locked --all --lib --examples --document-private-items --keep-going \
		--target-dir $(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	echo "Open Rust docs at file://$(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs/doc/{{DEFAULT_DOCS_PATH}}"


# cleans most of our crates, doesn't clean grpc gens, they are sometimes slow to build
clean:
	cargo clean \
		-p ark-lib \
		-p ark-testing \
		-p aspd-log \
		-p bark-aspd \
		-p bark-bitcoin-ext \
		-p bark-client \
		-p bark-json

# run a single clippy lint
clippy LINT:
	cargo clippy -- -A clippy::all -W clippy::{{LINT}}


default-aspd-config:
	cargo run -p bark-aspd --example dump-default-config > {{DEFAULT_ASPD_CONFIG_PATH}}
	echo "Default aspd config file written to {{DEFAULT_ASPD_CONFIG_PATH}}"

dump-aspd-sql-schema:
	cargo run -p ark-testing --example dump-aspd-postgres-schema > {{ASPD_SQL_SCHEMA_PATH}}
	# Use sed to remove lines that are hard to reproduce across different systems
	sed -i '/^-- Dumped by .*$/d' {{ASPD_SQL_SCHEMA_PATH}}
	sed -i '/^-- Dumped from .*$/d' {{ASPD_SQL_SCHEMA_PATH}}
	echo "aspd SQL schema written to {{ASPD_SQL_SCHEMA_PATH}}"

dump-bark-sql-schema:
	cargo run -p bark-client --example dump-sqlite-schema > {{BARK_SQL_SCHEMA_PATH}}
	echo "bark SQL schema written to {{BARK_SQL_SCHEMA_PATH}}"

