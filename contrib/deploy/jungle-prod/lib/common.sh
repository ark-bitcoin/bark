# Shared settings and helpers. Sourced by the scripts in this directory.
# shellcheck shell=bash

JP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Build host (ark-build) ---------------------------------------------------
REPO_URL="${REPO_URL:-https://github.com/SatoshiPortal/scuttle.git}"
SCUTTLE_HOME="${SCUTTLE_HOME:-/srv/scuttle}"
SRC_DIR="$SCUTTLE_HOME/src"
RELEASES_DIR="$SCUTTLE_HOME/releases"
VENDOR_DIR="$SCUTTLE_HOME/vendor"
LOG_DIR="$SCUTTLE_HOME/logs"
FLAKE_TARGET="bark-server-x86_64-unknown-linux-musl"

# --- Targets: role -> 10.42 address ---------------------------------------------
# The role is also the name used on the command line. Targets are always reached
# over the private backend network (10.42.0.0/24) from ark-build.
declare -A HOST_ADDR=(
	[captaind]=10.42.0.20
	[watchmand]=10.42.0.21
	[cln]=10.42.0.22
)
# The systemd unit that runs each role.
declare -A HOST_UNIT=(
	[captaind]=captaind.service
	[watchmand]=watchmand.service
	[cln]=lightningd.service
)
ALL_ROLES=(captaind watchmand cln)

DEPLOY_USER="${DEPLOY_USER:-debian}"
DEPLOY_KEY="${DEPLOY_KEY:-$HOME/.ssh/id_ed25519_scuttle_deploy}"
TARGET_ROOT=/opt/scuttle
KEEP_RELEASES="${KEEP_RELEASES:-5}"

SSH_OPTS=(-i "$DEPLOY_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes)

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# Source the nix profile when nix is not on PATH (non-login ssh sessions).
ensure_nix() {
	command -v nix >/dev/null 2>&1 && return 0
	# shellcheck disable=SC1091
	. /nix/var/nix/profiles/default/etc/profile.d/nix-daemon.sh
	command -v nix >/dev/null 2>&1 || die "nix not found; run bootstrap-build-host.sh"
}

valid_role() {
	local r
	for r in "${ALL_ROLES[@]}"; do [[ "$r" == "$1" ]] && return 0; done
	return 1
}

# Run a command on a role's host. Arguments are passed through as one shell
# command line, so quote them at the call site.
remote() {
	local role="$1"; shift
	ssh "${SSH_OPTS[@]}" "$DEPLOY_USER@${HOST_ADDR[$role]}" "$@"
}

# rsync to a role's host as root.
remote_rsync() {
	local role="$1"; shift
	rsync -e "ssh ${SSH_OPTS[*]}" --rsync-path="sudo rsync" "$@"
}
