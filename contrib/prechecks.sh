
# We don't want to run formatting on auto-generated files
RUST_FILES="$(git ls-files *.rs \
  | git check-attr --stdin linguist-generated \
  | sed '/: linguist-generated: true/d' \
  | sed 's/: linguist-generated: .*//g' \
)"

# We don't allow any line that starts with a whitespace
function rust_no_spaces_for_indent() {
  for filename in $RUST_FILES; do
    output=$(grep -n '^ ' $filename)
    status_code=$?

    if [ $status_code -eq 0 ]; then
      echo "Format error in '$filename"
      echo "$output"
      exit 1
    elif [ $status_code -eq 2 ]; then
      echo "An error occurred"
      echo $output
      exit 2
    fi
  done
}

# Check if there are structure log messages in aspd-logs that are not used.
function unused_aspd_logs() {
	ok=0
	rg "pub struct " ./aspd-log/src/msgs | cut -d ' ' -f 3 | while read -r log; do
		if ! rg -trust --quiet "slog.\($log" ./aspd/src/; then
			echo "UNUSED: $log"
			ok=1
		fi
	done
	exit "$ok"
}

# Check if the function exists and execute it
if declare -f "$1" > /dev/null; then
    "$@"
else
    echo "Function '$1' not found!"
    exit 1
fi
