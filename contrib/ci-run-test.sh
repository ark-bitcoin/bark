#!/usr/bin/env sh

TEST_VERSION="${1:-}"
if [ -z "$TEST_VERSION" ]; then
  echo "Error: TEST_VERSION argument is required" >&2
  exit 1
fi

# -----------------------------------------
# - State flag – prevent double execution -
# -----------------------------------------
ACTION_DONE=0   # 0 = none, 1 = copy, 2 = trash

copy() {
  if [ "$ACTION_DONE" -ne 0 ]; then return; fi
  ACTION_DONE=1
  echo "Running copy test data command..."
  bash ./contrib/ci-run-test-copy.sh || echo "Warning: copy failed" >&2
}

trash() {
  if [ "$ACTION_DONE" -ne 0 ]; then return; fi
  ACTION_DONE=2
  echo "Running trash (deleting test data)..."
  bash ./contrib/ci-run-test-trash.sh || echo "Warning: trash failed" >&2
}

trap 'copy' EXIT INT TERM

(
  sleep 3300
  echo "Watchdog: 55-minute timeout reached – forcing copy"
  copy
  kill -TERM "$PPID" 2>/dev/null || true
) &
WATCHDOG_PID=$!

echo "Starting test for version: $TEST_VERSION"
nix develop .#default --command bash -c "just '${TEST_VERSION}'"
TASK_EXIT_CODE=$?

if kill "$WATCHDOG_PID" 2>/dev/null; then
  wait "$WATCHDOG_PID" 2>/dev/null || true
fi

trap - EXIT INT TERM

if [ "$TASK_EXIT_CODE" -eq 0 ] && [ "${KEEP_ALL_TEST_DATA:-}" != "1" ] && [ "${CI_CODECOV_PIPELINE:-}" != "true" ]; then
  trash
else
  copy
fi

exit "$TASK_EXIT_CODE"