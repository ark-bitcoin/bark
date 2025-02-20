#!/usr/bin/env sh

if git diff --quiet HEAD -- aspd/config.default.toml; then
  echo "aspd/config.default.toml is unchanged."
else
  echo "aspd/config.default.toml is out-of-sync." >&2
  git diff HEAD -- aspd/config.default.toml
  exit 1
fi