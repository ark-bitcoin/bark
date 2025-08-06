#!/usr/bin/env sh
set -eu

[ "$#" -eq 1 ] || { printf '[ERROR] Usage: %s <tag-name>\n' "$0" >&2; exit 1; }
TAG_NAME=$1

log_info() { printf '[INFO] %s\n' "$1"; }
log_error() { printf '[ERROR] %s\n' "$1" >&2; exit 1; }

probe() { curl -sfL "$1" >/dev/null; }

check_release_exists() {
  tag_to_probe=$1
  if probe "https://codeberg.org/api/v1/repos/ark-bitcoin/bark/releases/tags/${tag_to_probe}"; then
    log_error "${tag_to_probe} already exists."
  fi
  log_info "Release ${tag_to_probe} is free to use."
}

VERSION=
case "${TAG_NAME}" in
  server-*) VERSION=${TAG_NAME#server-} ;;
  bark-*) VERSION=${TAG_NAME#bark-} ;;
  *)      log_error "Unknown tag ${TAG_NAME}." ;;
esac

[ -n "${VERSION}" ] || log_error "Tag ${TAG_NAME} is missing a version number."

check_release_exists "${TAG_NAME}"
