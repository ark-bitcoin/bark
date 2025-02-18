#!/usr/bin/env sh

git diff-index --quiet HEAD -- || {
  echo "Working tree is not clean." >&2
  exit 1
}
