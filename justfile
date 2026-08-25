# Find the target directory
CARGO_TARGET := `cargo metadata --format-version 1 --no-deps | jq -r '.target_directory'`
JUSTFILE_DIR := justfile_directory()
export CAPTAIND_EXEC := env("CAPTAIND_EXEC", CARGO_TARGET / "debug" / "captaind")
export WATCHMAND_EXEC := env("WATCHMAND_EXEC", CARGO_TARGET / "debug" / "watchmand")
export BARK_EXEC := env("BARK_EXEC", CARGO_TARGET / "debug" / "bark")
export BARKD_EXEC := env("BARKD_EXEC", CARGO_TARGET / "debug" / "barkd")
export BITCOIND_SNAPSHOT_DIR := JUSTFILE_DIR / "test" / "_bitcoind_snapshot"

NEXTEST_PROFILE := env("NEXTEST_PROFILE", "default")

SERVER_SQL_SCHEMA_PATH := "server/schema.sql"
BARK_SQL_SCHEMA_PATH := "bark/schema.sql"
BARK_OPENAPI_SCHEMA_PATH := "bark-rest/openapi.json"
BARK_REST_CLIENT_DIR := "bark-rest-client"

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

check-wasm-tests:
	ARK_CONTROL_URL="" ARK_ESPLORA_URL="" ARK_SERVER_URL="" \
		cargo check -p wasm-testing --tests \
		--no-default-features --features wasm \
		--target wasm32-unknown-unknown

check-lib-arithmetic:
	cargo clippy -p ark-lib --tests

check-fuzz:
	cargo check --manifest-path fuzz/Cargo.toml

check-release:
	cargo check --release -p bark-cli -p bark-server

check-bark-as-libs:
	cargo check -p ark-lib
	cargo check -p ark-lib --no-default-features
	cargo check -p bark-bitcoin-ext
	cargo check -p bark-bitcoin-ext --no-default-features
	cargo check -p bark-wallet
	cargo check -p bark-wallet -F native --no-default-features
	cargo check -p bark-json
	cargo check -p bark-json --no-default-features
	cargo check -p bark-rest
	cargo check -p bark-rest --no-default-features
	cargo check -p bark-rest-client

# Confirms bark-wallet is still consumable as a plain crates.io dependency.
check-use-bark-as-dependency:
	rm -rf barktest
	cargo init barktest
	cd barktest && cargo add bark-wallet && cargo update && cargo build

checks: prechecks check-lib-arithmetic check-wasm-tests check

check-commits:
	bash contrib/check-commits.sh

build:
	cargo version
	cargo build --workspace

build-ci:
	cargo version
	cargo build --profile ci --workspace --bins --examples

build-unit-tests-ci:
	cargo nextest archive --cargo-profile ci --workspace --exclude ark-testing \
		--archive-file {{CARGO_TARGET}}/ci/unit-tests.tar.zst --zstd-level 19

build-integration-tests-ci:
	cargo nextest archive --cargo-profile ci --package ark-testing \
		--archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst --zstd-level 19

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

build-msrv-lib:
	cd testing/msrv-lib && cargo build

build-bark-wasm:
	cargo build --target wasm32-unknown-unknown --lib --no-default-features \
		-p ark-lib --features wasm-web
	cargo build --target wasm32-unknown-unknown --lib --no-default-features \
		-p bark-bitcoin-ext --features wasm-web
	cargo build --target wasm32-unknown-unknown --lib --no-default-features \
		-p bark-server-rpc --features tonic-web
	cargo build --target wasm32-unknown-unknown --lib --no-default-features \
		-p bark-wallet --features wasm-web
	cargo build --target wasm32-unknown-unknown --lib --no-default-features \
		-p bark-wallet --features wasm-web,indexed-db

build-lib-wasm-release:
	cd lib/ && cargo build --release --target wasm32-unknown-unknown --lib --features wasm-web

docker-pull:
	if [ -n "${LIGHTNINGD_DOCKER_IMAGE-""}" ]; then docker image inspect "$LIGHTNINGD_DOCKER_IMAGE" > /dev/null 2>&1 && echo "Image already exists locally." || (echo "Image not found locally. Pulling..." && docker pull "$LIGHTNINGD_DOCKER_IMAGE"); fi

test-unit TEST="":
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --workspace \
		--exclude ark-testing {{TEST}}
alias unit := test-unit

test-unit-prebuilt:
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/unit-tests.tar.zst

test-doc:
	cargo test --doc

test-unit-codecov TEST="":
	cargo llvm-cov nextest --profile {{NEXTEST_PROFILE}} --workspace \
		--exclude ark-testing --no-report {{TEST}}

test-integration TEST="": ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		-E 'not binary(tor)' {{TEST}}
alias int := test-integration

# run integration tests for bark and barkd test files only
test-integration-bark: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		--test bark --test barkd
alias int-bark := test-integration-bark

# Run the integration tests that drive wallet actions (bark, barkd, bark-sdk)
# double-driving every action step (BARK_DOUBLE_DRIVE_ACTIONS) to check
# reentrancy.
[doc("run the bark/barkd/bark-sdk integration tests double-driving every action step to check reentrancy")]
test-integration-bark-int-action-reentrancy TEST="": ensure-build-bins docker-pull
	BARK_DOUBLE_DRIVE_ACTIONS=1 \
		cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		--test bark --test barkd --test bark-sdk {{TEST}}
alias int-bark-int-action-reentrancy := test-integration-bark-int-action-reentrancy

# Must not run under backward-compat mode (BARK_EXEC override has no effect
# on tests linked against the current bark-wallet crate).
test-integration-bark-sdk: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		--test bark-sdk
alias int-bark-sdk := test-integration-bark-sdk

# run tor integration tests
test-integration-tor: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		--test tor
alias int-tor := test-integration-tor

# run integration tests for core and server test files only
test-integration-core: ensure-build-bins docker-pull
	cargo nextest run --no-fail-fast --profile {{NEXTEST_PROFILE}} --package ark-testing \
		--test core --test server
alias int-core := test-integration-core

test-integration-prebuilt TEST="": docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst {{TEST}}

test-integration-bark-prebuilt: docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst \
		-E 'binary(bark) + binary(barkd)'

test-integration-bark-sdk-prebuilt: docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst \
		-E 'binary(=bark-sdk)'

test-integration-core-prebuilt: docker-pull
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst \
		-E 'binary(core) + binary(server)'

test-integration-bark-int-prebuilt: docker-pull
	RUST_MIN_STACK=33554432 \
	cargo nextest run --archive-file {{CARGO_TARGET}}/ci/integration-tests.tar.zst \
		-E 'binary(bark) + binary(barkd) + binary(=bark-sdk)'

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
	CHAIN_SOURCE=esplora cargo nextest run --profile {{NEXTEST_PROFILE}} \
		--package ark-testing {{TEST}}

test-integration-mempool TEST="": ensure-build-bins docker-pull
	CHAIN_SOURCE=mempool just int "{{TEST}}"
alias int-mempool := test-integration-mempool

test-integration-mempool-codecov TEST="": docker-pull
	#!/usr/bin/env bash
	set -euo pipefail
	source <(cargo llvm-cov show-env --export-prefix)
	CHAIN_SOURCE=mempool cargo nextest run --profile {{NEXTEST_PROFILE}} \
		--package ark-testing {{TEST}}

test-integration-all-codecov: docker-pull
	just test-integration-codecov
	just test-integration-mempool-codecov
alias int-all-cov := test-integration-all-codecov

test-all-codecov:
	just test-unit-codecov
	just test-integration-all-codecov
test: test-unit test-integration test-integration-esplora test-integration-mempool

test-wasm TEST="": ensure-build-bins docker-pull
	CHAIN_SOURCE=esplora cargo run -p wasm-testing --bin wasm-test-suite --features=bin -- "{{TEST}}"
alias wasm := test-wasm

test-wasm-unit:
	wasm-pack test --headless --firefox bark-runtime --lib
alias wasm-unit := test-wasm-unit

test-bark-wasm-indexed-db:
	wasm-pack test --headless --firefox bark --no-default-features --features 'indexed-db wasm-web' --lib

codecov-report:
	cargo llvm-cov report --html --output-dir "./target/debug/codecov/"

RUSTDOCSDIR := justfile_directory() / "rustdocs"
# This is opinionated, but doesn't matter. Any page has full search.
DEFAULT_DOCS_PATH := "bark/struct.Wallet.html"

# Generate rustdoc documentation for all crates and dependencies
[unix]
rustdocs ARG="":
	mkdir -p {{RUSTDOCSDIR}}
	cargo doc --target-dir {{RUSTDOCSDIR}} --locked --all --lib --examples {{ARG}} \
		--features "onchain-bdk indexed-db"
	echo "Open Rust docs at file://{{RUSTDOCSDIR}}/doc/{{DEFAULT_DOCS_PATH}}"

[windows]
rustdocs ARG="":
	set shell := ["cmd.exe"]
	# Repetitive because I'm currently unable to create a named variable
	# sed is converting C:\path\to\justfile_folder into /c/path/to/justfile_folder
	mkdir -p $(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' | sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	cargo doc --locked --all --lib --examples --keep-going {{ARG}} \
		--target-dir $(echo "{{JUSTFILE_DIR}}" \
		| sed 's|\\\\|/|g' \
		| sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs
	echo "Open Rust docs at file://$(echo "{{JUSTFILE_DIR}}" | sed 's|\\\\|/|g' \
		| sed 's|^\([a-zA-Z]\):|/\L\1|')/rustdocs/doc/{{DEFAULT_DOCS_PATH}}"

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
		| sed '/^\\unrestrict.*$/d' > {{SERVER_SQL_SCHEMA_PATH}}.tmp \
			&& mv {{SERVER_SQL_SCHEMA_PATH}}.tmp {{SERVER_SQL_SCHEMA_PATH}}
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
	#!/usr/bin/env bash
	# BARK_REST_VERSION is read here (not as a top-level `:=` binding) so it
	# reflects any bump that ran earlier in the same `just` invocation,
	# e.g. `release-new-version` → `bump-workspace-versions` → this recipe.
	set -euo pipefail
	BARK_REST_VERSION=$(grep '^version = ' bark-rest/Cargo.toml | sed -E 's/^version = "([^"]+)"/\1/')
	rm -rf {{BARK_REST_CLIENT_DIR}}
	openapi-generator-cli generate \
		-i {{BARK_OPENAPI_SCHEMA_PATH}} \
		-g rust \
		-o {{BARK_REST_CLIENT_DIR}} \
		--package-name bark-rest-client \
		--artifact-version "$BARK_REST_VERSION" \
		--additional-properties packageVersion="$BARK_REST_VERSION" \
		--additional-properties reqwestDefaultFeatures="rustls"
	cargo add --package bark-rest-client --path bark-json
	cargo add --package bark-rest-client --path bark-rest --no-default-features
	rm {{BARK_REST_CLIENT_DIR}}/src/models/*.rs
	cp bark-rest/helpers/models.rs {{BARK_REST_CLIENT_DIR}}/src/models/mod.rs

# Append server-rpc's version to ALLOWED_BARK_VERSIONS in
# server/src/telemetry.rs if not already listed. Idempotent; never
# removes.
update-allowed-bark-versions:
	#!/usr/bin/env bash
	set -euo pipefail
	target="server/src/telemetry.rs"
	rpc_cargo="server-rpc/Cargo.toml"
	cur=$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$rpc_cargo" | head -n1)
	if [[ -z "$cur" ]]; then
		echo "couldn't find version = \"X.Y.Z\" in $rpc_cargo" >&2
		exit 1
	fi
	existing=$(awk '$0 == "const ALLOWED_BARK_VERSIONS: &[&str] = &[" { on=1; next } \
	                on && $0 == "];" { on=0 } \
	                on' "$target" \
	         | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' \
	         | tr -d '"')
	if [[ -z "$existing" ]]; then
		echo "couldn't find ALLOWED_BARK_VERSIONS block in $target" >&2
		exit 1
	fi
	if grep -qxF "$cur" <<<"$existing"; then
		n=$(wc -l <<<"$existing")
		echo "$cur already present in ALLOWED_BARK_VERSIONS ($n entries); no change"
		exit 0
	fi
	# Sort by (length desc, semver asc) so output is stable and readable.
	sorted=$(printf '%s\n%s\n' "$existing" "$cur" | sort -u | awk '
		{ vals[NR] = $0 }
		END {
			for (i = 1; i <= NR; i++)
				for (j = 1; j <= NR - i; j++) {
					a = vals[j]; b = vals[j+1]
					la = length(a); lb = length(b)
					if (la < lb || (la == lb && semver_gt(a, b))) {
						vals[j] = b; vals[j+1] = a
					}
				}
			for (i = 1; i <= NR; i++) print vals[i]
		}
		function semver_gt(a, b,   ax, bx, i) {
			split(a, ax, "."); split(b, bx, ".")
			for (i = 1; i <= 3; i++) {
				if (ax[i]+0 > bx[i]+0) return 1
				if (ax[i]+0 < bx[i]+0) return 0
			}
			return 0
		}')
	# 5-per-line, tab-indented.
	formatted=$(echo "$sorted" | awk '
		BEGIN { line = ""; n = 0 }
		{
			if (n == 0) line = "\t\"" $0 "\","
			else        line = line " \"" $0 "\","
			n++
			if (n == 5) { print line; line = ""; n = 0 }
		}
		END { if (n > 0) print line }')
	tmp=$(mktemp)
	awk -v block="$formatted" '
		$0 == "const ALLOWED_BARK_VERSIONS: &[&str] = &[" {
			print
			print block
			skip = 1; next
		}
		skip && $0 == "];" { skip = 0; print; next }
		!skip { print }
	' "$target" > "$tmp"
	mv "$tmp" "$target"
	total=$(wc -l <<<"$sorted")
	echo "added $cur → $target ($total entries total)"

generate-static-files: dump-server-sql-schema dump-bark-sql-schema generate-bark-rest-client update-allowed-bark-versions

# Bump lockstep-group Cargo.toml versions to NEW_VERSION (idempotent).
bump-workspace-versions NEW_VERSION:
	bash contrib/bump-workspace-versions.sh {{NEW_VERSION}}

# Release cut: bump versions, regen derived files, verify build.
# Changelog, commit, tag, and push are manual. See contrib/agents/skills/release-tagging.md.
release-new-version NEW_VERSION: (bump-workspace-versions NEW_VERSION) generate-static-files checks
	#!/usr/bin/env bash
	set -euo pipefail
	echo ""
	echo "Workspace bumped, derived state refreshed, and build verified for v{{NEW_VERSION}}."
	echo ""
	echo "Next steps (manual, see contrib/agents/skills/release-tagging.md):"
	echo "  1. Review the diff. Verify Cargo.toml bumps hit every lockstep"
	echo "     crate and no unrelated external deps got dragged along."
	echo "  2. Merge unreleased CHANGELOG entries into CHANGELOG.md"
	echo "     (bash contrib/dump-unreleased-changelog.sh --remove to dump + clear)."
	echo "  3. git commit -am 'Release v{{NEW_VERSION}}'"
	echo "  4. Push the branch and open a merge request."
	echo "  5. After the MR is merged, tag the merge commit on master and push:"
	echo "       git tag bark-{{NEW_VERSION}} <merge-commit>"
	echo "       git push origin bark-{{NEW_VERSION}}"

# `build-msrv-lib` is invoked separately from the Dockerfile because it needs
# the .#msrv-lib nix shell rather than .#default.
[doc("pre-run every CI recipe so the CI base image ships with a warm build cache")]
ci-warmup: check build check-fuzz check-release check-bark-as-libs test-doc test-bark-wasm-indexed-db build-bark-wasm build-lib-wasm-release check-lib-arithmetic check-use-bark-as-dependency build-unit-tests-ci build-ci

cachix-push:
	nix develop .#default  --profile /tmp/bark-shell-dev      -c true
	nix develop .#build    --profile /tmp/bark-shell-build    -c true
	nix develop .#ci       --profile /tmp/bark-shell-ci       -c true
	nix develop .#msrv-lib --profile /tmp/bark-shell-msrv-lib -c true
	cachix push bark /tmp/bark-shell-dev
	cachix push bark /tmp/bark-shell-build
	cachix push bark /tmp/bark-shell-ci
	cachix push bark /tmp/bark-shell-msrv-lib

[doc("build a single nix release package and copy its binaries into build/ suffixed with the target triple")]
_nix-build-collect package target:
	#!/usr/bin/env bash
	set -euo pipefail
	mkdir -p build
	out=$(nix build --no-link --print-out-paths ${NIX_BUILD_FLAGS:-} ".#{{package}}-{{target}}")
	for bin in "$out"/bin/*
	do
		name=$(basename "$bin")
		if [[ "$name" == *.exe ]]; then
			dest="build/${name%.exe}-{{target}}.exe"
		else
			dest="build/$name-{{target}}"
		fi
		install -m 755 "$bin" "$dest"
		echo "$dest"
	done

# Builds the bark flake package with the right version stamp, mirroring
# bark-cli/build.rs: only a build of the commit carrying the bark-X.Y.Z
# release tag gets the clean release version, anything else gets the crate
# version with a -dev suffix (the package-bark.nix default). The nix
# sandbox can't see .git, so when the tag is present the version is passed
# in through the BARK_VERSION env var, which requires an impure build.
_nix-build-collect-bark target:
	#!/usr/bin/env bash
	set -euo pipefail
	tag=$(git tag --points-at HEAD | grep '^bark-' | head -n1 || true)
	if [ -z "$tag" ]; then
		just _nix-build-collect bark {{target}}
	else
		tag_version=${tag#bark-}
		crate_version=$(grep '^version = ' bark-cli/Cargo.toml | sed -E 's/^version = "([^"]+)"/\1/')
		if [ "$tag_version" != "$crate_version" ]; then
			echo "warning: tag version $tag_version differs from bark-cli/Cargo.toml version $crate_version, using the tag version" >&2
		fi
		BARK_VERSION="$tag_version" NIX_BUILD_FLAGS=--impure \
			just _nix-build-collect bark {{target}}
	fi

nix-build-bark-all:
	#!/usr/bin/env bash
	set -euo pipefail
	for target in \
		x86_64-unknown-linux-gnu \
		x86_64-unknown-linux-musl \
		aarch64-unknown-linux-musl \
		armv7-unknown-linux-musleabihf \
		x86_64-apple-darwin \
		aarch64-apple-darwin \
		x86_64-pc-windows-gnu
	do
		just _nix-build-collect-bark "$target"
	done
	just _nix-build-checksums

# The linux bark artifacts only, used by the nightly release.
nix-build-bark-linux:
	#!/usr/bin/env bash
	set -euo pipefail
	for target in \
		x86_64-unknown-linux-gnu \
		x86_64-unknown-linux-musl \
		aarch64-unknown-linux-musl \
		armv7-unknown-linux-musleabihf
	do
		just _nix-build-collect-bark "$target"
	done
	just _nix-build-checksums

# Same as _nix-build-collect-bark but for the server package, keyed on the
# server-X.Y.Z release tag and the SERVER_VERSION env var.
_nix-build-collect-server target:
	#!/usr/bin/env bash
	set -euo pipefail
	tag=$(git tag --points-at HEAD | grep '^server-' | head -n1 || true)
	if [ -z "$tag" ]; then
		just _nix-build-collect bark-server {{target}}
	else
		tag_version=${tag#server-}
		crate_version=$(grep '^version = ' server/Cargo.toml | sed -E 's/^version = "([^"]+)"/\1/')
		if [ "$tag_version" != "$crate_version" ]; then
			echo "warning: tag version $tag_version differs from server/Cargo.toml version $crate_version, using the tag version" >&2
		fi
		SERVER_VERSION="$tag_version" NIX_BUILD_FLAGS=--impure \
			just _nix-build-collect bark-server {{target}}
	fi

nix-build-server-all:
	#!/usr/bin/env bash
	set -euo pipefail
	for target in \
		x86_64-unknown-linux-gnu \
		x86_64-unknown-linux-musl
	do
		just _nix-build-collect-server "$target"
	done
	just _nix-build-checksums

nix-build-all: nix-build-bark-all nix-build-server-all

# Regenerates build/SHA256SUMS over all collected artifacts. Removed first so
# the glob can't pick up a stale copy and hash the file into itself; LC_ALL=C
# so the ordering doesn't depend on the locale.
_nix-build-checksums:
	#!/usr/bin/env bash
	set -euo pipefail
	cd build
	rm -f SHA256SUMS
	LC_ALL=C sha256sum * > SHA256SUMS
	cat SHA256SUMS
