#!/bin/sh

# Set up useful
BITCOIN_DATADIR=$PWD/test/bitcoindatadir
BITCOIN_CLI=bitcoin-cli
BITCOIND=bitcoind

BITCOIND_RPC_PORT=18443
BITCOIND_RPC_HOST=127.0.0.1
BITCOIND_URL=http://${BITCOIND_RPC_HOST}:${BITCOIND_RPC_PORT}
BITCOIND_COOKIE=$PWD/test/bitcoindatadir/regtest/.cookie

export DB_NAME=aspdb
export DB_USER=postgres
export DB_PASSWORD=postgres

mkdir -p ${BITCOIN_DATADIR}


# Define useful aliases
alias bcli="$BITCOIN_CLI -regtest --rpcconnect=$BITCOIND_RPC_HOST --rpcport=$BITCOIND_RPC_PORT --rpccookiefile=$BITCOIND_COOKIE"
alias aspd="cargo run --bin aspd --"
alias bark="cargo run --bin bark --"
alias bd="$BITCOIND -regtest -datadir=${BITCOIN_DATADIR} -server -txindex -fallbackfee=0.0002"

# Print some help and documentation
echo "-------------------------------------------"
echo "- Ark Demo                                -"
echo "-------------------------------------------"
echo ""
echo "This script is useful to test and demo ark "
echo "on regtest. The script will help you to set-up"
echo "an ASP and a couple of clients that can send"
echo "ark payments to each-other."
echo ""
echo ""
echo "The following aliases have been defined"
echo "- \`bd\`: To run and start \`bitcoind\`"
echo "- \`bcli\`: Use \`bitcoin-cli\` on your \`bitcoind\`"
echo "- \`aspd\`: Compiles and runs \`aspd\`"
echo "- \`bark\`: Compiles and runs \`bark\`"
echo ""
