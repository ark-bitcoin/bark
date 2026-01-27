#!/usr/bin/env bash
# Dump unreleased changelog entries into CHANGELOG.md format
#
# Usage:
echo "usage: ./contrib/dump-unreleased-changelog.sh [--remove]"
echo ""
#
# Options:
#   --remove    Remove the unreleased entry files after processing
#
# This script:
# - Lists all subdirectories in CHANGELOG/unreleased/
# - For each target (e.g., bark, server, ark-lib), outputs all entries
# - Optionally removes the entry files (but keeps directories)

set -euo pipefail

REMOVE=false
CHANGELOG_DIR="CHANGELOG/unreleased"

# Parse arguments
while [[ $# -gt 0 ]]; do
	case $1 in
		--remove)
			REMOVE=true
			shift
			;;
		*)
			echo "Unknown option: $1" >&2
			echo "Usage: $0 [--remove]" >&2
			exit 1
			;;
	esac
done

# Check if unreleased directory exists
if [[ ! -d "$CHANGELOG_DIR" ]]; then
	echo "Error: $CHANGELOG_DIR directory not found" >&2
	exit 1
fi

# Find all target directories (subdirectories of unreleased/)
mapfile -t targets < <(find "$CHANGELOG_DIR" -mindepth 1 -maxdepth 1 \
	-type d | sort)

if [[ ${#targets[@]} -eq 0 ]]; then
	echo "No unreleased changelog targets found" >&2
	exit 0
fi

echo ""
echo ""

# Process each target
for target_dir in "${targets[@]}"; do
	target=$(basename "$target_dir")
	echo "- \`$target\`"

	# Find all entry files in this target directory
	mapfile -t entries < <(find "$target_dir" -type f ! -name 'template.md' \
		| sort)

	# Print content of each entry, indented by 2 spaces
	for entry in "${entries[@]}"; do
		while IFS= read -r line; do
			echo "  $line"
		done < "$entry"
	done

	# Remove entry files if requested (but keep directory)
	if [[ "$REMOVE" == true ]]; then
		for entry in "${entries[@]}"; do
			rm "$entry"
		done
	fi

	echo ""
done
