#!/usr/bin/env sh

TEST_VERSION=$1
if [ -z "${TEST_VERSION}" ]; then
  exit 1
fi

# Define cleanup function
cleanup() {
  echo "Running cleanup..."
  bash ./contrib/ci-run-test-copy.sh
}

# Set trap for script exit (covers normal exit and termination signals)
trap cleanup EXIT INT TERM

# Start watchdog in the background (55 minutes = 3300 seconds)
(
  sleep 3300
  echo "Watchdog: Approaching timeout, triggering cleanup"
  cleanup
  kill $$  # Terminate the main process
) &

WATCHDOG_PID=$!

# Run main task
nix --extra-experimental-features 'nix-command flakes' develop .#default --command bash -c "just '${TEST_VERSION}'"
TASK_EXIT_CODE=$?

# Kill the watchdog if main task finishes first
kill "$WATCHDOG_PID" 2>/dev/null
wait "$WATCHDOG_PID" 2>/dev/null

# Exit with the same code as the main task
exit $TASK_EXIT_CODE