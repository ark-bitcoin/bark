#!/usr/bin/env bash
# Deploy a release from the build host to one or more roles.
#
#   deploy.sh [--restart] [--keep N] <release|latest> <role>... | all
#
# <release> is a commit (or unique prefix) under $SCUTTLE_HOME/releases.
# Roles: captaind, watchmand, cln. Default: install and flip /opt/scuttle/current
# but do NOT restart the service. Idempotent: re-running with the same release
# changes nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

RESTART=0
KEEP="$KEEP_RELEASES"
ARGS=()
while [[ $# -gt 0 ]]; do
	case "$1" in
		--restart) RESTART=1 ;;
		--keep) KEEP="$2"; shift ;;
		-h|--help) sed -n '2,10p' "$0"; exit 0 ;;
		*) ARGS+=("$1") ;;
	esac
	shift
done
[[ ${#ARGS[@]} -ge 2 ]] || die "usage: deploy.sh [--restart] [--keep N] <release|latest> <role>...|all"

RELNAME="${ARGS[0]}"
ROLES=("${ARGS[@]:1}")
[[ "${ROLES[0]}" == all ]] && ROLES=("${ALL_ROLES[@]}")
for r in "${ROLES[@]}"; do valid_role "$r" || die "unknown role '$r' (${ALL_ROLES[*]})"; done

# Resolve latest / unique commit prefix.
if [[ "$RELNAME" == latest ]]; then
	COMMIT="$(readlink "$RELEASES_DIR/latest")" || die "no latest release"
else
	mapfile -t M < <(cd "$RELEASES_DIR" && ls -d "$RELNAME"* 2>/dev/null | grep -E '^[0-9a-f]{40}$' || true)
	[[ ${#M[@]} -eq 1 ]] || die "release '$RELNAME' matches ${#M[@]} releases in $RELEASES_DIR"
	COMMIT="${M[0]}"
fi
REL="$RELEASES_DIR/$COMMIT"
log "release $COMMIT"

CAPTAIND_BIN="$REL/captaind/bin/captaind"

deploy_role() {
	local role="$1"
	local src="$REL/$role"
	local addr="${HOST_ADDR[$role]}"
	local unit="${HOST_UNIT[$role]}"
	local dest="$TARGET_ROOT/releases/$COMMIT"
	log "== $role ($addr)"

	( cd "$src" && sha256sum -c --quiet SHA256SUMS ) || die "local checksum mismatch in $src"

	# Transfer (skipped when the verified release is already on the target).
	if remote "$role" "sudo test -d '$dest' && cd '$dest' && sudo sha256sum -c --quiet SHA256SUMS" 2>/dev/null; then
		log "release already on target"
	else
		local linkdest=()
		remote "$role" "test -d '$TARGET_ROOT/current/'" && linkdest=(--link-dest="$TARGET_ROOT/current/")
		remote "$role" "sudo mkdir -p '$TARGET_ROOT/releases' && sudo rm -rf '$dest.partial'"
		remote_rsync "$role" -a --chown=root:root "${linkdest[@]}" "$src/" "$DEPLOY_USER@$addr:$dest.partial/"
		remote "$role" "cd '$dest.partial' && sudo sha256sum -c --quiet SHA256SUMS && sudo mv -T '$dest.partial' '$dest'" \
			|| die "checksum mismatch on $role after transfer"
		log "transferred and verified"
	fi

	# Validate the new binary against the live config before switching to it.
	local cfgdir=""
	case "$role" in captaind) cfgdir=captaind ;; watchmand) cfgdir=watchmand ;; esac
	if [[ -n "$cfgdir" ]] && remote "$role" "sudo test -f /etc/$cfgdir/$cfgdir.toml"; then
		local flags=()
		[[ "$role" == watchmand ]] && flags=(--watchman)
		# The config holds secrets: copy it to a private temp dir on this host
		# for the check and remove it right after.
		local tmpd; tmpd="$(mktemp -d)"
		remote "$role" "sudo cat /etc/$cfgdir/$cfgdir.toml" >"$tmpd/$cfgdir.toml"
		local ok=0
		"$CAPTAIND_BIN" check-config "${flags[@]}" "$tmpd/$cfgdir.toml" >/dev/null 2>&1 || ok=1
		rm -rf "$tmpd"
		[[ $ok -eq 0 ]] || die "new release does not accept the live /etc/$cfgdir/$cfgdir.toml; fix the config or choose another release"
		log "config check ok ($role)"
	fi

	# Atomic flip + prune.
	remote "$role" "sudo bash -s" <<REMOTE
set -euo pipefail
cd '$TARGET_ROOT'
cur="\$(readlink current || true)"
if [[ "\$cur" != "releases/$COMMIT" ]]; then
	if [[ -n "\$cur" ]]; then ln -sfn "\$cur" previous.new && mv -T previous.new previous; fi
	ln -sfn "releases/$COMMIT" current.new && mv -T current.new current
	echo "current -> releases/$COMMIT (was: \${cur:-none})"
else
	echo "current already -> releases/$COMMIT"
fi
# Keep the newest $KEEP releases, never current or previous.
keep_cur="\$(basename "\$(readlink current)")"; keep_prev="\$(basename "\$(readlink previous 2>/dev/null || echo none)")"
ls -1t releases | grep -E '^[0-9a-f]{40}\$' | tail -n +\$(( $KEEP + 1 )) | while read -r r; do
	[[ "\$r" == "\$keep_cur" || "\$r" == "\$keep_prev" ]] && continue
	echo "pruning releases/\$r"; rm -rf "releases/\$r"
done
REMOTE

	if [[ $RESTART -eq 1 ]]; then
		log "restarting $unit"
		remote "$role" "sudo systemctl restart $unit"
	else
		local st; st="$(remote "$role" "systemctl is-active $unit" || true)"
		log "not restarting (unit $unit is: $st)"
		if [[ "$st" == active ]]; then log "WARNING: $unit still runs the previous binary until restarted"; fi
	fi
}

for r in "${ROLES[@]}"; do deploy_role "$r"; done
log "done"
