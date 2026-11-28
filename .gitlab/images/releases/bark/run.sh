#!/bin/sh
# Usage: <image> [bark|barkd] [args...]
#   no arguments      -> barkd start
#   bark|barkd ...    -> that binary with the remaining arguments
#   anything else     -> bark with all arguments
#
# With BARK_REGTEST_SETUP=1 (set by contrib/docker/docker-compose.yml) a missing
# wallet is first created against the regtest captaind of that compose file.

if [ "${1:-}" = "bark" ] || [ "${1:-}" = "barkd" ]; then
  BINARY="/usr/local/bin/$1"
  shift
elif [ $# -eq 0 ]; then
  BINARY="/usr/local/bin/barkd"
  set -- start
else
  BINARY="/usr/local/bin/bark"
fi

regtest_setup() {
  SERVER_URL="http://captaind:3535"
  BITCOIND_RPC_URL="http://bitcoind:18443"
  BITCOIND_RPC_USER="second"
  BITCOIND_RPC_PASS="ark"

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

  if [ -n "$ESPLORA_ADDRESS" ]; then
    /usr/local/bin/bark create --regtest --ark "${SERVER_URL}" --esplora "${ESPLORA_ADDRESS}"
  else
    /usr/local/bin/bark create --regtest --ark "${SERVER_URL}" \
      --bitcoind "${BITCOIND_RPC_URL}" --bitcoind-user "${BITCOIND_RPC_USER}" --bitcoind-pass "${BITCOIND_RPC_PASS}"
  fi
  sleep 2s
}

# Skip the setup when the command itself is `bark create`.
if [ "${BARK_REGTEST_SETUP:-}" = "1" ] && [ ! -d /root/.bark ] \
  && ! { [ "$BINARY" = "/usr/local/bin/bark" ] && [ "${1:-}" = "create" ]; }; then
  regtest_setup
fi

exec "$BINARY" "$@"
