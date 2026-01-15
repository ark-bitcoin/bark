#!/usr/bin/env sh

# We don't allow any line that starts with a whitespace
rust_no_spaces_for_indent() {
	ok=0

	for filename in $(git ls-files *.rs); do
		gen=$(echo "$filename" | git check-attr --stdin linguist-generated)
		case "$gen" in
			*"linguist-generated: set"*)
				echo "skipping file: $filename"
				continue ;;
		esac

		output=$(grep -n '^ ' "$filename")
		status_code=$?

		if [ $status_code -eq 0 ]; then
			echo "Format error in '$filename'"
			echo "$output"

			ok=2
		elif [ $status_code -eq 2 ]; then
			echo "An error occurred"
			echo "$output"

			ok=2
		fi
	done

	exit $ok
}

# We don't allow lines that only have whitespace
rust_no_whitespace_on_empty_lines() {
	ok=0

	for filename in $(git ls-files *.rs); do
		gen=$(echo "$filename" | git check-attr --stdin linguist-generated)
		case "$gen" in
			*"linguist-generated: set"*)
				echo "skipping file: $filename"
				continue ;;
		esac

		output=$(grep -nE '^[[:space:]]+$' "$filename")
		status_code=$?

		if [ $status_code -eq 0 ]; then
			echo "Format error in '$filename'"
			echo "$output"

			ok=2
		elif [ $status_code -eq 2 ]; then
			echo "An error occurred"
			echo "$output"

			ok=2
		fi
	done

	exit $ok
}

# Check if there are structure log messages in server-logs that are not used.
unused_server_logs() {
	ok=0

	# Use a temporary file instead of process substitution
	TMP_FILE=$(mktemp)
	grep -E "pub struct " ./server-log/src/msgs/* | sed 's/^.*pub struct //' | awk '{print $1}' > "$TMP_FILE"

	while read -r log; do
		if ! grep -r -E "slog.*\\(${log}" ./server/src/* > /dev/null 2>&1; then
			echo "UNUSED: '$log'"
			ok=2
		fi
	done < "$TMP_FILE"

	rm -f "$TMP_FILE"

	exit $ok
}

# Check for duplicate migration version numbers
conflicting_migration_scripts() {
	ok=0
	migration_dir="server/src/database/migrations"

	# Create temp file to track seen versions
	TMP_FILE=$(mktemp)

	for file in "$migration_dir"/*.sql; do
		filename=$(basename "$file")
		# Extract version number: strip V or U prefix, then get number before __
		version=$(echo "$filename" | sed -E 's/^[VU]([0-9]+)__.*/\1/')

		# Check if we've seen this version before
		existing=$(grep "^${version}:" "$TMP_FILE" || true)
		if [ -n "$existing" ]; then
			other_file=$(echo "$existing" | cut -d: -f2)
			echo "Conflicting migration versions:"
			echo "  $other_file"
			echo "  $filename"
			ok=2
		else
			echo "${version}:${filename}" >> "$TMP_FILE"
		fi
	done

	rm -f "$TMP_FILE"
	exit $ok
}

# Check if the function exists and execute it
if command -v "$1" > /dev/null 2>&1; then
	"$@"
else
	echo "Function '$1' not found!"

	exit 2
fi
