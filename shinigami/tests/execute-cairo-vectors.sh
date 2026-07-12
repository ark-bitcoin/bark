#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
scarb_version="$(scarb --version)"
case "$scarb_version" in
	"scarb 2.18.0"*) ;;
	*)
		echo "expected Scarb 2.18.0, found: $scarb_version" >&2
		exit 1
		;;
esac

fixture_dir="$(mktemp -d)"
trap 'rm -rf -- "$fixture_dir"' EXIT
mkdir -p "$fixture_dir/src"
cp "$repo_root/shinigami/tests/fixtures/ark_taproot_miniscript_claim_v1.cairo" \
	"$fixture_dir/src/lib.cairo"

cat > "$fixture_dir/Scarb.toml" <<'EOF'
[package]
name = "bark_shinigami_cairo_fixture"
version = "0.1.0"
edition = "2024_07"

[dependencies]
cairo_execute = "2.18.0"

[dev-dependencies]
cairo_test = "2.18.0"

[cairo]
sierra-replace-ids = true
enable-gas = false

[[target.executable]]
EOF

(
	cd "$fixture_dir"
	scarb test
	scarb build
	for input in "$repo_root"/shinigami/tests/vectors/*.input.json; do
		echo "executing $(basename "$input")"
		scarb execute --no-build --arguments-file "$input" --print-program-output
	done
)
