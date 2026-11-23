#!/usr/bin/env bash
# Build a Scuttle release on the build host (ark-build).
#
#   build.sh [--force] [<git ref>]        default ref: scuttle
#
# Produces $SCUTTLE_HOME/releases/<full commit>/ with one directory per target
# role (captaind, watchmand, cln), a SHA256SUMS in each, and a MANIFEST.
# Building a commit that already has a release is a no-op unless --force.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

FORCE=0
if [[ "${1:-}" == "--force" ]]; then FORCE=1; shift; fi
REF="${1:-scuttle}"
KEEP_BUILD_RELEASES="${KEEP_BUILD_RELEASES:-10}"
# Number of distinct pinned signers that must have signed the CLN SHA256SUMS.
CLN_MIN_SIGS="${CLN_MIN_SIGS:-3}"

ensure_nix
mkdir -p "$RELEASES_DIR" "$VENDOR_DIR" "$LOG_DIR"
exec 9>"$SCUTTLE_HOME/build.lock"
flock -n 9 || die "another build is running"

# --- Resolve the ref ----------------------------------------------------------
log "fetching $REPO_URL"
git -C "$SRC_DIR" fetch --quiet --tags --prune --force "$REPO_URL" \
	'+refs/heads/*:refs/remotes/origin/*'
if ! COMMIT="$(git -C "$SRC_DIR" rev-parse --verify -q "refs/remotes/origin/$REF^{commit}")"; then
	COMMIT="$(git -C "$SRC_DIR" rev-parse --verify -q "$REF^{commit}")" \
		|| die "cannot resolve ref '$REF'"
fi
log "ref $REF -> $COMMIT"

REL="$RELEASES_DIR/$COMMIT"
if [[ -d "$REL" && $FORCE -eq 0 ]]; then
	log "release exists: $REL (use --force to rebuild)"
	ln -sfn "$COMMIT" "$RELEASES_DIR/latest"
	exit 0
fi

BUILD_LOG="$LOG_DIR/build-${COMMIT:0:12}-$(date -u +%Y%m%dT%H%M%SZ).log"
log "full log: $BUILD_LOG"
exec > >(tee -a "$BUILD_LOG") 2>&1

# Give nix a ref that contains the commit, so any commit (not just a branch
# tip) is fetchable from the local checkout.
git -C "$SRC_DIR" update-ref refs/jp/build "$COMMIT"
FLAKE_REF="git+file://$SRC_DIR?ref=refs/jp/build&rev=$COMMIT"

# --- Pins from the commit's own nix/dev-shell.nix ------------------------------
DEVSHELL="$(git -C "$SRC_DIR" show "$COMMIT:nix/dev-shell.nix")"
CLN_VERSION="$(sed -n 's/^[[:space:]]*lightningVersion = "\(.*\)";/\1/p' <<<"$DEVSHELL")"
HOLD_REV="$(sed -n 's/^[[:space:]]*holdPluginRevision = "\(.*\)";/\1/p' <<<"$DEVSHELL")"
[[ -n "$CLN_VERSION" && -n "$HOLD_REV" ]] || die "cannot parse CLN/hold pins from nix/dev-shell.nix"
# nix's SRI hash of the clightning release zip, converted to hex.
CLN_ZIP_SRI="$(awk '/clightning-v\$\{lightningVersion\}\.zip/{f=1} f && /hash = /{print; exit}' <<<"$DEVSHELL" \
	| sed -n 's/.*hash = "sha256-\(.*\)";.*/\1/p')"
CLN_ZIP_HEX="$(base64 -d <<<"$CLN_ZIP_SRI" | od -An -tx1 | tr -d ' \n')"
[[ ${#CLN_ZIP_HEX} -eq 64 ]] || die "cannot parse the clightning zip hash pin"
log "pins: CLN $CLN_VERSION, hold $HOLD_REV"

# --- CLN release: download, verify signatures + checksums ------------------------
fetch_cln() {
	local d="$VENDOR_DIR/cln-$CLN_VERSION"
	local base="https://github.com/ElementsProject/lightning/releases/download/v$CLN_VERSION"
	local tarball="clightning-v$CLN_VERSION-Ubuntu-22.04-amd64.tar.xz"
	local sums="SHA256SUMS-v$CLN_VERSION"
	mkdir -p "$d"
	if [[ -f "$d/.verified" && -d "$d/tree/usr" ]]; then
		log "CLN $CLN_VERSION already verified"; return
	fi
	( cd "$d"
		for f in "$sums" "$sums.asc" "$tarball"; do
			[[ -f "$f" ]] || curl -fsSL -o "$f" "$base/$f"
		done
		local gh; gh="$(mktemp -d)"; chmod 700 "$gh"
		GNUPGHOME="$gh" gpg --batch -q --import "$JP_DIR/keys/cln-release-signers.asc"
		local good
		good="$(GNUPGHOME="$gh" gpg --batch --status-fd 1 --verify "$sums.asc" "$sums" 2>/dev/null \
			| awk '$2=="VALIDSIG"{print $NF}' | sort -u \
			| grep -cFx -f "$JP_DIR/keys/cln-release-signers.fingerprints" || true)"
		rm -rf "$gh"
		[[ "$good" -ge "$CLN_MIN_SIGS" ]] \
			|| die "CLN SHA256SUMS has $good valid pinned signatures, need $CLN_MIN_SIGS"
		log "CLN SHA256SUMS: $good valid signatures from pinned signers"
		grep -F "  $tarball" "$sums" | sha256sum -c - >&2
		# The nix pin builds the zip; it must be the exact zip the signers signed.
		grep -qFx "$CLN_ZIP_HEX  clightning-v$CLN_VERSION.zip" "$sums" \
			|| die "nix/dev-shell.nix zip hash is not the signed release zip"
		rm -rf tree && mkdir tree && tar xf "$tarball" -C tree
		touch .verified
	)
}
fetch_cln

# --- Build captaind + watchmand (static musl) and the hold plugin ----------------
log "nix build $FLAKE_TARGET"
SERVER_OUT="$(nix build --no-link --print-out-paths -L "$FLAKE_REF#$FLAKE_TARGET" | tail -1)"
log "nix build hold plugin"
HOLD_OUT="$(nix build --no-link --print-out-paths -L --impure \
	--file "$JP_DIR/nix/hold-plugin.nix" --argstr flake "$FLAKE_REF" | tail -1)"

# The hold plugin must run on the targets' glibc (Debian 12: 2.36).
HOLD_MAX_GLIBC="$(tail -1 "$HOLD_OUT/glibc-symbols.txt" | sed 's/GLIBC_//')"
[[ "$(printf '%s\n' "$HOLD_MAX_GLIBC" 2.36 | sort -V | tail -1)" == 2.36 ]] \
	|| die "hold plugin needs glibc $HOLD_MAX_GLIBC, targets have 2.36"
[[ "$(cat "$HOLD_OUT/rev")" == "$HOLD_REV" ]] || die "hold plugin built from an unexpected revision"

# --- Assemble ----------------------------------------------------------------
STAGE="$RELEASES_DIR/.stage-$COMMIT"
rm -rf "$STAGE"
mkdir -p "$STAGE"/{captaind/bin,watchmand/bin,cln/plugins-extra}
install -m 0755 "$SERVER_OUT/bin/captaind" "$STAGE/captaind/bin/captaind"
install -m 0755 "$SERVER_OUT/bin/watchmand" "$STAGE/watchmand/bin/watchmand"
install -m 0755 "$HOLD_OUT/bin/hold" "$STAGE/cln/plugins-extra/hold"
cp -al "$VENDOR_DIR/cln-$CLN_VERSION/tree/usr" "$STAGE/cln/usr"

CAPTAIND_VERSION="$("$STAGE/captaind/bin/captaind" --version)"
WATCHMAND_VERSION="$("$STAGE/watchmand/bin/watchmand" --version)"
LDD_OUT="$(ldd "$STAGE/captaind/bin/captaind" 2>&1 || true)"
if grep -q "not a dynamic" <<<"$LDD_OUT"; then LINKAGE=static; else LINKAGE=dynamic; fi
[[ "$LINKAGE" == static ]] || die "captaind is not statically linked"

MANIFEST="$STAGE/MANIFEST"
{
	echo "commit: $COMMIT"
	echo "ref: $REF"
	echo "flake.lock sha256: $(git -C "$SRC_DIR" show "$COMMIT:flake.lock" | sha256sum | cut -d' ' -f1)"
	echo "build date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
	echo "build host: $(hostname)"
	echo "nix: $(nix --version)"
	echo "flake target: $FLAKE_TARGET"
	echo "captaind: $CAPTAIND_VERSION ($LINKAGE)"
	echo "watchmand: $WATCHMAND_VERSION ($LINKAGE)"
	echo "cln: $CLN_VERSION (upstream Ubuntu-22.04-amd64 release, signature + checksum verified)"
	echo "cln tarball sha256: $(sha256sum "$VENDOR_DIR/cln-$CLN_VERSION/clightning-v$CLN_VERSION-Ubuntu-22.04-amd64.tar.xz" | cut -d' ' -f1)"
	echo "hold plugin rev: $HOLD_REV"
	echo "hold plugin needs: $(tr '\n' ' ' <"$HOLD_OUT/needed-libs.txt")"
	echo "hold plugin max glibc symbol: $(tail -1 "$HOLD_OUT/glibc-symbols.txt")"
} >"$MANIFEST"
for r in captaind watchmand cln; do cp "$MANIFEST" "$STAGE/$r/MANIFEST"; done

for r in captaind watchmand cln; do
	( cd "$STAGE/$r" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS )
done
( cd "$STAGE" && sha256sum captaind/bin/captaind watchmand/bin/watchmand cln/plugins-extra/hold >SHA256SUMS )
{ echo; echo "sha256:"; sed 's/^/  /' "$STAGE/SHA256SUMS"; } >>"$STAGE/MANIFEST"

rm -rf "$REL"
mv "$STAGE" "$REL"
ln -sfn "$COMMIT" "$RELEASES_DIR/latest"

# Prune old releases on the build host (never `latest`).
mapfile -t OLD < <(cd "$RELEASES_DIR" && find . -mindepth 1 -maxdepth 1 -type d ! -name '.stage-*' -printf '%T@ %f\n' \
	| sort -rn | awk -v k="$KEEP_BUILD_RELEASES" 'NR>k{print $2}')
for o in "${OLD[@]}"; do
	[[ "$o" == "$COMMIT" ]] && continue
	log "pruning old release $o"; rm -rf "${RELEASES_DIR:?}/$o"
done

log "release ready: $REL"
cat "$REL/MANIFEST"
