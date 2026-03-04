#!/bin/sh
export SERVER_URL="http://captaind:3535"
export BITCOIND_RPC_URL="http://bitcoind:18443"
export BITCOIND_RPC_USER="second"
export BITCOIND_RPC_PASS="ark"

ADDRESS="${SERVER_URL#*://}"
HOST=${ADDRESS%%:*}
PORT=${ADDRESS##*:}

MAX_ATTEMPTS=10
DELAY_BETWEEN_ATTEMPTS=3

attempt=1

while true; do
  if echo "quit" | telnet "$HOST" "$PORT" 2>/dev/null | grep -q "Connected"; then
    echo "Service is up on $HOST:$PORT"
    break
  fi

  echo "Waiting for $HOST:$PORT (attempt $attempt)..."
  sleep "${DELAY_BETWEEN_ATTEMPTS}s"

  attempt=$((attempt + 1))
  if [ "$attempt" -gt "${MAX_ATTEMPTS}" ]; then
    echo "Timeout waiting for $HOST:$PORT"
    break
  fi
done

if [ -d /root/.bark ]; then
  echo "Bark already created"
else
  if [ -n "$ESPLORA_ADDRESS" ]; then
  	/usr/local/bin/bark create --regtest --ark "${SERVER_URL}" --esplora "${ESPLORA_ADDRESS}"
  else
  	/usr/local/bin/bark create --regtest --ark "${SERVER_URL}" \
      --bitcoind "${BITCOIND_RPC_URL}" --bitcoind-user "${BITCOIND_RPC_USER}" --bitcoind-pass "${BITCOIND_RPC_PASS}"
  fi
  sleep 2s
fi

# If the first argument is exactly "bark" or "barkd", treat it as the binary name
# and shift it away so the rest of the command line goes directly to that binary.
if [ "${1:-}" = "bark" ] || [ "${1:-}" = "barkd" ]; then
  BINARY="/usr/local/bin/$1"
  shift  # remove the "bark" or "barkd"
  exec "$BINARY" "$@"
else
  # No explicit binary name given → default behaviour:
  #   - when starting the service normally no argument at all
  #   	=> start the daemon (barkd)
  #   - when running a one-off command that doesn't start with bark/barkd
  #     => assume it's a bark subcommand
  if [ $# -eq 0 ]; then
    # No arguments at all → this is "docker compose up bark" → start daemon
    exec /usr/local/bin/barkd start
  else
    # Something was passed but not "bark"/"barkd" → treat as bark subcommand
    exec /usr/local/bin/bark "$@"
  fi
fi