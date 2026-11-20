#!/usr/bin/env bash
# Funds a fresh signet deployment from the miner's coinbases:
# - captaind's rounds wallet (VTXO pool and rounds) and watchman wallet;
# - the external CLN node, which then opens a channel to the Ark server's
#   node and pushes half of it across, so both sides can pay.
#
# Mining continues at 10-minute blocks, so this script mines the
# confirmations it needs itself. Run it once after setup.sh.
set -euo pipefail

DATA=/var/lib/scuttle
PREFIX=/opt/scuttle
ROUNDS_BTC="${ROUNDS_BTC:-20}"
WATCHMAN_BTC="${WATCHMAN_BTC:-1}"
CLN_BTC="${CLN_BTC:-5}"
CHANNEL_SAT="${CHANNEL_SAT:-200000000}"

cli() { sudo -u scuttle bitcoin-cli -datadir="$DATA/bitcoind" -signet "$@"; }
mine() { sudo -u scuttle "$PREFIX/bin/signet-mine" "$1" >/dev/null; }
lncli() { sudo docker exec "scuttle-$1" lightning-cli --network=signet --lightning-dir=/data/.lightning "${@:2}"; }

# Coinbases need 100 confirmations. Mine until the miner can pay for all.
need=$(awk "BEGIN{print $ROUNDS_BTC + $WATCHMAN_BTC + $CLN_BTC + 1}")
while awk "BEGIN{exit !($(cli -rpcwallet=miner getbalance) < $need)}"; do
	mine 50
done

wallets=$(sudo -u scuttle "$PREFIX/bin/captaind" rpc wallet)
rounds=$(echo "$wallets" | jq -r .rounds.address)
# watchmand logs its wallet's next address; there is no RPC for it.
watchman=$(sudo journalctl -u scuttle-watchmand --no-pager -o cat \
	| grep -o '"next_address":"[^"]*' | tail -1 | cut -d'"' -f4)
external=$(lncli cln-external newaddr | jq -r .bech32)

# Fund once: a rerun only finishes the channel.
if [ "$(echo "$wallets" | jq .rounds.total_balance)" = 0 ]; then
	echo "rounds   $rounds   $ROUNDS_BTC BTC"
	echo "watchman $watchman $WATCHMAN_BTC BTC"
	echo "external $external $CLN_BTC BTC"
	cli -rpcwallet=miner send "{\"$rounds\": $ROUNDS_BTC, \"$watchman\": $WATCHMAN_BTC, \"$external\": $CLN_BTC}" >/dev/null
	mine 6
fi

# Open a channel from the external node to the Ark server's node.
if [ "$(lncli cln-external listpeerchannels | jq '.channels | length')" -gt 0 ]; then
	echo "channel already open"
	exit 0
fi
internal_id=$(lncli cln-internal getinfo | jq -r .id)
lncli cln-external connect "$internal_id" 127.0.0.1 9735 >/dev/null
for i in $(seq 1 60); do
	[ "$(lncli cln-external listfunds | jq '[.outputs[] | select(.status == "confirmed")] | length')" -gt 0 ] && break
	sleep 2
done
lncli cln-external -k fundchannel id="$internal_id" amount="$CHANNEL_SAT" \
	push_msat=$((CHANNEL_SAT * 500)) >/dev/null
mine 6
for i in $(seq 1 60); do
	state=$(lncli cln-external listpeerchannels "$internal_id" | jq -r '.channels[0].state')
	[ "$state" = CHANNELD_NORMAL ] && break
	sleep 2
done
echo "channel: $state"
sudo -u scuttle "$PREFIX/bin/captaind" rpc wallet | jq -c "{rounds_sat: .rounds.total_balance}"
