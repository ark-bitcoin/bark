#!/usr/bin/env sh
# Bump lockstep-group crate versions to NEW_VERSION. Idempotent.
# Usage: bump-workspace-versions.sh NEW_VERSION
set -eu

log_info() { echo "[INFO] $1"; }
log_error() { echo "[ERROR] $1" >&2; exit 1; }

[ $# -eq 1 ] || log_error "Usage: $0 NEW_VERSION"

new_ver=$1
echo "$new_ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
	|| log_error "NEW_VERSION must match X.Y.Z, got: $new_ver"

# Cargo.toml files that release in lockstep.
lockstep="
	bark-cli/Cargo.toml
	bark-common/Cargo.toml
	bark-json/Cargo.toml
	bark-rest-client/Cargo.toml
	bark-rest/Cargo.toml
	bark/Cargo.toml
	bitcoin-ext/Cargo.toml
	lib/Cargo.toml
	server-log/Cargo.toml
	server-rpc/Cargo.toml
	server/Cargo.toml
"

# Package names for the lockstep crates. Scopes the cross-crate dep sweep.
packages="
	bark-cli
	bark-common
	bark-json
	bark-rest-client
	bark-rest
	bark-wallet
	bark-bitcoin-ext
	ark-lib
	bark-server-log
	bark-server-rpc
	bark-server
"

lockstep_count=$(echo $lockstep | wc -w)

# Read every observed version before touching anything: each crate's
# [package].version AND every internal-dep pin (`<pkg> = ...version = "..."`
# where <pkg> is in $packages). Including pins in the observed set means
# a stale pin left behind by a partial prior run counts as drift, so we
# either repair it via the sweep or refuse if it disagrees with the rest.
old_vers=""
for f in $lockstep; do
	v=$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$f" | head -n1)
	[ -n "$v" ] || log_error "couldn't find [package].version in $f"
	old_vers="$old_vers $v"
	for pkg in $packages; do
		pins=$(sed -nE "/^${pkg} = /s/.*version = \"([0-9]+\.[0-9]+\.[0-9]+)\".*/\1/p" "$f")
		for p in $pins; do
			old_vers="$old_vers $p"
		done
	done
done

# Refuse on drift: one string swap can't reconcile mixed starting versions.
unique_count=$(printf '%s\n' $old_vers | sort -u | wc -l)
if [ "$unique_count" -gt 1 ]; then
	echo "lockstep crates/pins are at mixed versions; refusing to sweep. Observed:" >&2
	printf '%s\n' $old_vers | sort -u | sed 's/^/  /' >&2
	exit 1
fi
old_ver=$(printf '%s\n' $old_vers | sort -u)
if [ "$old_ver" = "$new_ver" ]; then
	log_info "workspace already at $new_ver ($lockstep_count lockstep crates); no change"
	exit 0
fi

# Three-phase update so a mid-run failure can't leave the workspace mixed:
#   1. Stage: sed every manifest into a fresh <f>.new.$$ tmp; no sources touched.
#   2. Validate: postflight the staged files (both [package].version and pins).
#   3. Commit: back up each source to <f>.bak.$$, then mv <f>.new.$$ over it.
# Trap on EXIT: on failure, restore any already-committed sources from their
# .bak.$$ and remove all .new.$$ tmps. On success, drop the .bak.$$ backups.
# .new.$$ / .bak.$$ suffixes carry the pid so a stale tmp from a crashed
# prior run can't collide with this one.
old_pat=$(echo "$old_ver" | sed 's/\./\\./g')
new_suf=".new.$$"
bak_suf=".bak.$$"
_committed=""
_success=0

cleanup() {
	if [ "$_success" -eq 0 ]; then
		for cf in $_committed; do
			[ -f "$cf$bak_suf" ] && mv -f "$cf$bak_suf" "$cf"
		done
	fi
	for f in $lockstep; do
		rm -f "$f$new_suf" "$f$bak_suf"
	done
}
trap cleanup EXIT

# Phase 1: stage.
total=0
staged=""
for f in $lockstep; do
	n=$(grep -cE "^version = \"$old_pat\"" "$f" || true)
	for pkg in $packages; do
		m=$(grep -cE "^${pkg} = .*version = \"$old_pat\"" "$f" || true)
		n=$((n + m))
	done
	if [ "$n" -gt 0 ]; then
		set -- -E -e "s/^version = \"$old_pat\"/version = \"$new_ver\"/"
		for pkg in $packages; do
			set -- "$@" -e "/^${pkg} = /s/version = \"$old_pat\"/version = \"$new_ver\"/g"
		done
		sed "$@" "$f" > "$f$new_suf" || log_error "sed failed on $f (staging)"
		staged="$staged $f"
		printf "  %s: %d version pin(s) staged\n" "$f" "$n"
		total=$((total + n))
	else
		printf "  %s: no change (expected %s not found)\n" "$f" "$old_ver"
	fi
done

# Phase 2: validate staged files. Same postflight expectations as before but
# read from <f>.new.$$ so sources are still untouched if this rejects.
fail=0
for f in $staged; do
	sf="$f$new_suf"
	v=$(sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$sf" | head -n1)
	if [ "$v" != "$new_ver" ]; then
		printf "  ERR: staged %s [package].version is %s, not %s\n" "$f" "$v" "$new_ver" >&2
		fail=1
	fi
	for pkg in $packages; do
		pins=$(sed -nE "/^${pkg} = /s/.*version = \"([0-9]+\.[0-9]+\.[0-9]+)\".*/\1/p" "$sf")
		for p in $pins; do
			if [ "$p" != "$new_ver" ]; then
				printf "  ERR: staged %s pin %s is %s, not %s\n" "$f" "$pkg" "$p" "$new_ver" >&2
				fail=1
			fi
		done
	done
done
[ "$fail" -eq 0 ] || log_error "staging validation failed; sources untouched"

# Phase 3: commit. Back up source, then mv staged over it. Any failure here
# triggers the trap, which restores previously-committed sources from .bak.$$.
for f in $staged; do
	cp -p "$f" "$f$bak_suf" || log_error "backup failed for $f"
	mv "$f$new_suf" "$f" || log_error "commit failed for $f"
	_committed="$_committed $f"
done

_success=1

log_info "bumped $old_ver to $new_ver across $lockstep_count lockstep crates ($total lines)"
