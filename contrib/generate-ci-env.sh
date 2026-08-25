#!/usr/bin/env bash
# Generates the devShell env payloads used by the contrib/ci-env/<shell>.sh
# entry scripts.
#
# Runs in the CI prechecks job; the payloads travel to the other jobs as
# artifacts, so each job can enter a devShell by sourcing a file instead
# of paying a flake evaluation. The payloads are not committed: they are
# regenerated from the checkout's own nix files every pipeline, so they
# can never go stale.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

for shell in ci default msrv-lib; do
	echo "Generating contrib/ci-env/$shell.env..."
	nix print-dev-env ".#$shell" > "contrib/ci-env/$shell.env"
done
