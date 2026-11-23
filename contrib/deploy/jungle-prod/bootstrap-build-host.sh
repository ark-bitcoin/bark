#!/usr/bin/env bash
# One-time (idempotent) setup of the build host ark-build: multi-user nix with
# flakes, the repo checkout over https, and the directory layout.
#
# Run as the unprivileged login user (sudo is needed). Safe to re-run.
set -euo pipefail

NIX_VERSION="${NIX_VERSION:-2.24.10}"
# SHA-256 of nix-$NIX_VERSION-x86_64-linux.tar.xz, as published next to the
# tarball at releases.nixos.org. Verified below; bump both together.
NIX_TARBALL_SHA256="${NIX_TARBALL_SHA256:-ec1023e4c0e01da4bbec64c19e9a2bc94d36feae421402abbf3a2db848a1c6b5}"

REPO_URL="${REPO_URL:-https://github.com/SatoshiPortal/scuttle.git}"
SCUTTLE_HOME="${SCUTTLE_HOME:-/srv/scuttle}"

if [[ ! -d /nix/store ]]; then
	work="$(mktemp -d)"
	trap 'rm -rf "$work"' EXIT
	cd "$work"
	tarball="nix-$NIX_VERSION-x86_64-linux.tar.xz"
	curl -fsSLO "https://releases.nixos.org/nix/nix-$NIX_VERSION/$tarball"
	echo "$NIX_TARBALL_SHA256  $tarball" | sha256sum -c -
	tar xf "$tarball"
	sudo "./nix-$NIX_VERSION-x86_64-linux/install" --daemon --yes
fi

if ! grep -qs '^experimental-features' /etc/nix/nix.conf; then
	echo "experimental-features = nix-command flakes" | sudo tee -a /etc/nix/nix.conf >/dev/null
	sudo systemctl restart nix-daemon
fi

sudo mkdir -p "$SCUTTLE_HOME"
sudo chown "$USER": "$SCUTTLE_HOME"
mkdir -p "$SCUTTLE_HOME"/{releases,vendor,logs}
[[ -d "$SCUTTLE_HOME/src/.git" ]] || git clone "$REPO_URL" "$SCUTTLE_HOME/src"

# Dedicated deploy key; authorize its public key on the targets (see README).
key="$HOME/.ssh/id_ed25519_scuttle_deploy"
if [[ ! -f "$key" ]]; then
	ssh-keygen -q -t ed25519 -N '' -C "scuttle-deploy@$(hostname)" -f "$key"
fi
echo "deploy public key:"; cat "$key.pub"
