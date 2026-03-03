#!/usr/bin/env sh
#
# Check if a path argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <file-or-directory>" >&2
  exit 1
fi

PATH_ARG="$1"

if git diff -w --quiet HEAD -- "$PATH_ARG"; then
  echo "$PATH_ARG is unchanged."
else
  echo "$PATH_ARG is out-of-sync." >&2
  git diff -w HEAD -- "$PATH_ARG"
  exit 1
fi
