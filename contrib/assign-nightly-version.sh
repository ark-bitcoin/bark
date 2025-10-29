#!/usr/bin/env sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION_NAME=$1

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

[ -z "$VERSION_NAME" ] && log_error "VERSION_NAME argument is required"

BARK_CARGO="$REPO_ROOT/bark/Cargo.toml"

[ ! -f "$BARK_CARGO" ] && log_error "bark/Cargo.toml does not exist"
[ ! -r "$BARK_CARGO" ] && log_error "Cannot read bark/Cargo.toml"

BASE_VERSION=$(sed -n '/^\[package\]/,/^\[/ s/^version = "\([^"]*\)"/\1/p' "$BARK_CARGO" | head -n 1)
[ -z "$BASE_VERSION" ] && log_error "No version found in bark/Cargo.toml"

log_info "Found version $BASE_VERSION in bark/Cargo.toml"

log_info "Searching for Cargo.toml files in $REPO_ROOT"
find "$REPO_ROOT" -type f -name "Cargo.toml" | while read -r cargo_file; do
    log_info "Processing $cargo_file"

    [ ! -r "$cargo_file" ] && log_error "Cannot read $cargo_file"
    [ ! -w "$cargo_file" ] && log_error "Cannot write to $cargo_file"

	if sed "s/$BASE_VERSION/$BASE_VERSION-${VERSION_NAME}/g" "$cargo_file" > "$cargo_file.tmp"; then
		diff "$cargo_file.tmp" "$cargo_file" || true
		if mv "$cargo_file.tmp" "$cargo_file"; then
			log_info "Updated version in $cargo_file"
		else
			rm -f "$cargo_file.tmp"
			log_error "Failed to move $cargo_file.tmp to $cargo_file"
		fi
    else
        rm -f "$cargo_file.tmp"
        log_error "Failed to update $cargo_file"
    fi
done

log_info "All Cargo.toml files updated successfully"