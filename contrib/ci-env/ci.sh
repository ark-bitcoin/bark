#!/usr/bin/env bash
# Usage: ci.sh <command> [args...]
#
# Runs <command> inside the "ci" devShell, without the per-job flake
# evaluation when a pre-generated env payload is available. See _run.sh.
exec bash "$(dirname "${BASH_SOURCE[0]}")/_run.sh" ci "$@"
