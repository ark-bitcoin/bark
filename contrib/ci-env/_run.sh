#!/usr/bin/env bash
# Runs a command inside the given devShell. Used by the sibling
# <shell>.sh entry scripts; not meant to be invoked directly.
#
# When a pre-generated env payload (<shell>.env, produced by
# contrib/generate-ci-env.sh in the CI prechecks job and handed to the
# other jobs as an artifact) is present and every store path it
# references exists locally, the payload is sourced directly -- no
# flake evaluation. In every other situation (no artifact: local use,
# pipelines without prechecks; or store paths missing: the nix files
# changed and this container's store predates them) this falls back to
# a real `nix develop`, which substitutes or builds whatever is missing.
#
# CI_SHELL_FORCE_FLAKE=1 forces the `nix develop` path.
set -euo pipefail

shell="${1:?usage: _run.sh <shell> <command> [args...]}"
shift
: "${1:?usage: _run.sh <shell> <command> [args...]}"

payload="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$shell.env"

payload_ok() {
	[ "${CI_SHELL_FORCE_FLAKE:-}" != "1" ] || return 1
	[ -r "$payload" ] || return 1
	# All store paths in the payload must exist. Skip nix's all-e
	# placeholder hashes, which never exist on disk.
	local p
	while IFS= read -r p; do
		[ -e "$p" ] || return 1
	done < <(grep -oE '/nix/store/[a-z0-9]{32}-[0-9a-zA-Z+._-]+' "$payload" | grep -vE '/e{32}-' | sort -u)
}

if ! payload_ok; then
	echo "ci-env: no usable env payload for '$shell', using nix develop" >&2
	exec nix develop ".#$shell" --command "$@"
fi

# The payload is the same rc script `nix develop` sources (the shell env,
# with the caller's PATH appended at the end). It isn't written for
# `set -eu`, so relax while sourcing it. If sourcing fails, the env is
# only partially applied -- possibly with a PATH that misses the caller's
# entries, since the payload only re-appends those at its very end -- so
# restore PATH and fall back to `nix develop` rather than running the
# command in a broken environment. Anything needed after the sourcing is
# saved under ci_env_-prefixed names: the payload sets plenty of stdenv
# variables, including one that clobbers $shell.
ci_env_shell="$shell"
ci_env_saved_path="$PATH"
set +eu
# shellcheck disable=SC1090
. "$payload"
ci_env_rc=$?
set -eu
if [ "$ci_env_rc" -ne 0 ]; then
	PATH="$ci_env_saved_path"
	echo "ci-env: sourcing $payload failed, using nix develop" >&2
	exec nix develop ".#$ci_env_shell" --command "$@"
fi
exec "$@"
