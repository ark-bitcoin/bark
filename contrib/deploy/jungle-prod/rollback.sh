#!/usr/bin/env bash
# Flip /opt/scuttle/current on a role back to the previous release, or to a
# release that is still on the target.
#
#   rollback.sh [--restart] <role> [<release commit>]
#
# Default: no restart. A rollback is only a symlink flip, so it is instant.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

RESTART=0
if [[ "${1:-}" == "--restart" ]]; then RESTART=1; shift; fi
ROLE="${1:-}"; TO="${2:-}"
valid_role "$ROLE" || die "usage: rollback.sh [--restart] <${ALL_ROLES[*]}> [<release>]"

remote "$ROLE" "sudo bash -s" <<REMOTE
set -euo pipefail
cd '$TARGET_ROOT'
cur="\$(readlink current)"
if [[ -n '$TO' ]]; then
	target="releases/$TO"
else
	target="\$(readlink previous)" || { echo "no previous release recorded" >&2; exit 1; }
fi
[[ -d "\$target" ]] || { echo "\$target is not on this host" >&2; exit 1; }
if [[ "\$target" != "\$cur" ]]; then
	ln -sfn "\$cur" previous.new && mv -T previous.new previous
	ln -sfn "\$target" current.new && mv -T current.new current
fi
echo "current -> \$(readlink current), previous -> \$(readlink previous)"
REMOTE

if [[ $RESTART -eq 1 ]]; then
	remote "$ROLE" "sudo systemctl restart ${HOST_UNIT[$ROLE]}"
	log "restarted ${HOST_UNIT[$ROLE]}"
else
	log "not restarting; run: ssh ... sudo systemctl restart ${HOST_UNIT[$ROLE]}"
fi
