"""
Download a release binary, verify its sha256, and cache it.

Cache layout: <cache-dir>/<sha256>/<name>

Prints the absolute path to the cached binary on stdout.
"""

import argparse
import hashlib
import os
import stat
import sys
import urllib.request


def main():
	parser = argparse.ArgumentParser(description="Fetch and cache a release binary")
	parser.add_argument("--url", required=True, help="Download URL for the binary")
	parser.add_argument("--sha256", required=True, help="Expected sha256 hash")
	parser.add_argument("--cache-dir", default="/tmp/bark-releases", help="Cache directory")
	parser.add_argument("--name", default="bark", help="Binary name in the cache")
	args = parser.parse_args()

	dest_dir = os.path.join(args.cache_dir, args.sha256)
	dest = os.path.join(dest_dir, args.name)

	# Already cached — just print the path.
	if os.path.isfile(dest) and os.access(dest, os.X_OK):
		print(dest)
		return

	print(f"Downloading {args.name} from {args.url}", file=sys.stderr)
	os.makedirs(dest_dir, exist_ok=True)
	urllib.request.urlretrieve(args.url, dest)

	# Verify the sha256 hash.
	with open(dest, "rb") as f:
		actual = hashlib.sha256(f.read()).hexdigest()

	if actual != args.sha256:
		os.remove(dest)
		print(f"sha256 mismatch: expected {args.sha256}, got {actual}", file=sys.stderr)
		sys.exit(1)

	os.chmod(dest, os.stat(dest).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
	print(dest)


if __name__ == "__main__":
	main()
