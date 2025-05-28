#!/usr/bin/env sh
#
# Check if a file path argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <file-path>" >&2
  exit 1
fi

FILE="$1"

if git diff --quiet HEAD -- "$FILE"; then
  echo "$FILE is unchanged."
else
  echo "$FILE is out-of-sync." >&2
  git diff HEAD -- "$FILE"
  exit 1
fi
