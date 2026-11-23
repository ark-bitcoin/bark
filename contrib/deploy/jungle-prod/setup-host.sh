#!/usr/bin/env bash
# One-time (idempotent) preparation of a target host. Run from the build host.
#
#   setup-host.sh <role>... | all
#
# Installs OS packages, creates the service user and directories, installs the
# systemd unit and, only when absent, the config file from hosts/<role>/.
# Never enables or starts anything, never touches network config, and never
# creates keys or wallets.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

ROLES=("$@")
[[ ${#ROLES[@]} -ge 1 ]] || die "usage: setup-host.sh <${ALL_ROLES[*]}>...|all"
[[ "${ROLES[0]}" == all ]] && ROLES=("${ALL_ROLES[@]}")
for r in "${ROLES[@]}"; do valid_role "$r" || die "unknown role '$r'"; done

setup_role() {
	local role="$1" addr="${HOST_ADDR[$1]}"
	log "== setup $role ($addr)"
	local tmp="/tmp/scuttle-setup-$role"
	remote "$role" "rm -rf '$tmp' && mkdir -p '$tmp'"
	rsync -a -e "ssh ${SSH_OPTS[*]}" "$JP_DIR/hosts/$role/" "$DEPLOY_USER@$addr:$tmp/"

	remote "$role" "sudo ROLE=$role TMP=$tmp bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

pkgs=(ca-certificates rsync)
case "$ROLE" in
	# lightningd (upstream Ubuntu 22.04 build) and the hold plugin link these
	# against the host's libs; tor is installed as a package only.
	cln) pkgs+=(libpq5 libsodium23 libsqlite3-0 tor) ;;
esac
apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null

install -d -m 0755 /opt/scuttle /opt/scuttle/releases

mkuser() { # name
	id "$1" >/dev/null 2>&1 || useradd --system --home-dir "/var/lib/$1" --no-create-home \
		--shell /usr/sbin/nologin "$1"
}
# Install a config only when it does not exist; always refresh the .dist copy.
install_config() { # src dst owner-group
	install -m 0640 -o root -g "$3" "$1" "$2.dist"
	if [[ -e "$2" ]]; then echo "keeping existing $2"
	else install -m 0640 -o root -g "$3" "$1" "$2"; echo "installed $2 (placeholders to fill)"; fi
}
add_symlink() { ln -sfn "$1" "$2"; }

# systemd-resolved answers LLMNR on 0.0.0.0:5355 by default; nothing here needs it.
install -d /etc/systemd/resolved.conf.d
printf '[Resolve]\nLLMNR=no\nMulticastDNS=no\n' >/etc/systemd/resolved.conf.d/90-no-llmnr.conf
systemctl try-restart systemd-resolved

case "$ROLE" in
captaind)
	mkuser captaind
	install -d -m 0700 -o captaind -g captaind /var/lib/captaind
	install -d -m 0750 -o root -g captaind /etc/captaind /etc/captaind/cln /etc/captaind/cln/hold
	install_config "$TMP/captaind.toml" /etc/captaind/captaind.toml captaind
	install -m 0644 "$TMP/captaind.service" /etc/systemd/system/captaind.service
	add_symlink /opt/scuttle/current/bin/captaind /usr/local/bin/captaind
	# TLS names of the CLN plugin certs resolve to ark-cln on the backend net.
	# Proxmox cloud-init sets manage_etc_hosts: true, which rewrites
	# /etc/hosts from the template on every boot, so the entry goes in the
	# template as well as in the live file.
	for f in /etc/cloud/templates/hosts.debian.tmpl /etc/hosts; do
		[ -f "$f" ] || continue
		grep -q '# scuttle-jungle-prod' "$f" \
			|| printf '10.42.0.22 cln hold # scuttle-jungle-prod\n' >>"$f"
	done
	;;
watchmand)
	mkuser watchmand
	install -d -m 0700 -o watchmand -g watchmand /var/lib/watchmand
	install -d -m 0750 -o root -g watchmand /etc/watchmand
	install_config "$TMP/watchmand.toml" /etc/watchmand/watchmand.toml watchmand
	install -m 0644 "$TMP/watchmand.service" /etc/systemd/system/watchmand.service
	add_symlink /opt/scuttle/current/bin/watchmand /usr/local/bin/watchmand
	;;
cln)
	mkuser lightning
	install -d -m 0700 -o lightning -g lightning /var/lib/lightning
	install -d -m 0750 -o root -g lightning /etc/lightning
	install_config "$TMP/config" /etc/lightning/config lightning
	install -m 0644 "$TMP/lightningd.service" /etc/systemd/system/lightningd.service
	add_symlink /opt/scuttle/current/usr/bin/lightningd /usr/local/bin/lightningd
	add_symlink /opt/scuttle/current/usr/bin/lightning-cli /usr/local/bin/lightning-cli
	;;
esac
systemctl daemon-reload
rm -rf "$TMP"
REMOTE
}

for r in "${ROLES[@]}"; do setup_role "$r"; done
log "done (nothing enabled or started)"
