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

/usr/local/bin/bark "$@"
