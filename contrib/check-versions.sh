#!/usr/bin/env sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAG_NAME=$1

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

check_version() {
    project=$1
    prefix=$2

    PROJECT_DIR="$REPO_ROOT/$project"
    if [ ! -d "$PROJECT_DIR" ]; then
        log_error "ERROR: Project directory $PROJECT_DIR does not exist."
    fi

	cd "$PROJECT_DIR" || exit 1

    REF_VERSION="${TAG_NAME#"${prefix}"}"
    PROJECT_VERSION=$(nix develop .#default --command bash -c "cargo pkgid | cut -d '@' -f2 | cut -d ' ' -f1")

    if [ "$REF_VERSION" != "$PROJECT_VERSION" ]; then
        log_error "ERROR: COMMIT ($REF_VERSION) does not match ${project} ($PROJECT_VERSION)"
    else
        log_info "Version check passed: COMMIT matches ${project} ($REF_VERSION)"
    fi
}

case "$TAG_NAME" in
	server-*)
		check_version server server-
		;;
	bark-*)
		check_version bark bark-
		;;
esac

