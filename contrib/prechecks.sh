#!/usr/bin/env sh

# We don't allow any line that starts with a whitespace
rust_no_spaces_for_indent() {
	ok=0

	for filename in $(git ls-files *.rs); do
		gen=$(echo "$filename" | git check-attr --stdin linguist-generated)
		case "$gen" in
			*"linguist-generated: true"*)
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

# Check if there are structure log messages in aspd-logs that are not used.
unused_aspd_logs() {
	ok=0

	# Use a temporary file instead of process substitution
	TMP_FILE=$(mktemp)
	grep -E "pub struct " ./aspd-log/src/msgs/* | sed 's/^.*pub struct //' | awk '{print $1}' > "$TMP_FILE"

	while read -r log; do
		if ! grep -r -E "slog.*\\(${log}" ./aspd/src/* > /dev/null 2>&1; then
			echo "UNUSED: '$log'"
			ok=2
		fi
	done < "$TMP_FILE"

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
