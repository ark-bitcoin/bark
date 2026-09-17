"""
Download a release binary, verify its sha256, and cache it.

  --version 0.7.1        resolve the bark asset for this platform, hash from
                         the release's SHA256SUMS; use locally. Refetches
                         SHA256SUMS every run, so it needs the network.
  --url ... --sha256 ... name the asset outright; use in CI, to pin one
                         artifact, and for any binary other than bark

Cache layout: <cache-dir>/<sha256>/<name>

Prints the absolute path to the cached binary on stdout.
"""

import argparse
import hashlib
import os
import platform
import stat
import sys
import urllib.request

RELEASE_URL = "https://gitlab.com/ark-bitcoin/bark/-/releases/bark-{version}/downloads"

# Asset suffixes keyed by (system, machine), named by the `release-bark` job
# in .gitlab/bark-release.yml.
PLATFORMS = {
	("Darwin", "arm64"): "apple-aarch64",
	("Darwin", "aarch64"): "apple-aarch64",
	("Darwin", "x86_64"): "apple-x86_64",
	("Linux", "x86_64"): "linux-x86_64",
	("Linux", "aarch64"): "linux-arm64",
	("Linux", "arm64"): "linux-arm64",
	("Linux", "armv7l"): "linux-armv7",
}


def host_platform():
	key = (platform.system(), platform.machine())
	try:
		return PLATFORMS[key]
	except KeyError:
		known = ", ".join(sorted(set(PLATFORMS.values())))
		sys.exit(
			f"no bark release asset known for {key[0]}/{key[1]}. "
			f"Pass --platform with one of: {known}"
		)


def resolve(version, plat):
	"""URL and expected hash of the bark asset for `plat` in release `version`."""
	base = RELEASE_URL.format(version=version)
	asset = f"bark-{version}-{plat}"

	sums_url = f"{base}/SHA256SUMS"
	print(f"Resolving {asset} from {sums_url}", file=sys.stderr)
	with urllib.request.urlopen(sums_url) as resp:
		sums = resp.read().decode()

	for line in sums.splitlines():
		parts = line.split()
		if len(parts) == 2 and parts[1] == asset:
			return f"{base}/{asset}", parts[0]

	sys.exit(f"{asset} is not listed in {sums_url}; check the version and platform")


def main():
	parser = argparse.ArgumentParser(description="Fetch and cache a release binary")
	parser.add_argument("--version", help="Release version, e.g. 0.7.1 (resolves per platform)")
	parser.add_argument("--platform", help="Override the detected platform, e.g. apple-aarch64")
	parser.add_argument("--url", help="Download URL for the binary")
	parser.add_argument("--sha256", help="Expected sha256 hash")
	parser.add_argument("--cache-dir", default="/tmp/bark-releases", help="Cache directory")
	parser.add_argument("--name", default="bark", help="Binary name in the cache")
	args = parser.parse_args()

	if args.version:
		if args.url or args.sha256:
			parser.error("--version cannot be combined with --url/--sha256")
		# `resolve` only knows the bark release layout, so it would happily
		# fetch bark and cache it under another binary's name.
		if args.name != "bark":
			parser.error(f"--version only resolves bark releases, not {args.name}; pass --url/--sha256")
		url, sha256 = resolve(args.version, args.platform or host_platform())
	else:
		if not (args.url and args.sha256):
			parser.error("pass --version, or both --url and --sha256")
		url, sha256 = args.url, args.sha256

	dest_dir = os.path.join(args.cache_dir, sha256)
	dest = os.path.join(dest_dir, args.name)

	# Already cached — just print the path.
	if os.path.isfile(dest) and os.access(dest, os.X_OK):
		print(dest)
		return

	print(f"Downloading {args.name} from {url}", file=sys.stderr)
	os.makedirs(dest_dir, exist_ok=True)
	urllib.request.urlretrieve(url, dest)

	# Verify the sha256 hash.
	with open(dest, "rb") as f:
		actual = hashlib.sha256(f.read()).hexdigest()

	if actual != sha256:
		os.remove(dest)
		print(f"sha256 mismatch: expected {sha256}, got {actual}", file=sys.stderr)
		sys.exit(1)

	os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
	print(dest)


if __name__ == "__main__":
	main()
