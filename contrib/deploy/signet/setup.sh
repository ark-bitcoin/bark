#!/usr/bin/env bash
# Sets up a private custom signet with the whole scuttle stack on one
# Debian 13 VM: bitcoind with a 10-minute block miner, Postgres, two CLN
# nodes, captaind, watchmand, a forwarder barkd and posd.
#
# Run as a sudo user on the VM, from a checkout whose release binaries are
# built (target/release/{captaind,watchmand,barkd,bark,posd}). Safe to run
# again: it keeps existing secrets, keys, chain data and databases.
#
#   ./contrib/deploy/signet/setup.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
BIN_SRC="$REPO/target/release"
PREFIX=/opt/scuttle
DATA=/var/lib/scuttle
ETC=/etc/scuttle
CLN_IMAGE="${CLN_IMAGE:-secondark/cln-hold:v26.06.10-efc7d5f}"
# The URL phones use for posd. Pairing links and the Lightning address come
# from it. Over Tailscale Serve this is https://<host>.<tailnet>.ts.net.
PUBLIC_URL="${PUBLIC_URL:-http://$(hostname -I | awk '{print $1}'):3080}"

# The block interval. Signet retargets like mainnet, so blocks must come
# at the 10-minute target or difficulty climbs out of reach for a CPU.
BLOCK_INTERVAL_SECS=600
RPC_PORT=38332

log() { printf '\n== %s\n' "$*"; }
as_scuttle() { sudo -u scuttle -H "$@"; }

log "user, directories, binaries"
id scuttle >/dev/null 2>&1 || sudo useradd --system --create-home --home-dir "$DATA" --shell /usr/sbin/nologin scuttle
sudo usermod -aG docker scuttle
sudo install -d -o scuttle -g scuttle -m 750 "$DATA" "$DATA"/{bitcoind,captaind,watchmand,cln-internal,cln-external,barkd,posd,electrs}
sudo install -d -o root -g scuttle -m 750 "$ETC"
sudo install -d -m 755 "$PREFIX/bin"
for b in captaind watchmand barkd bark posd; do
	sudo install -m 755 "$BIN_SRC/$b" "$PREFIX/bin/$b"
done
# Blockstream electrs, built separately (see README).
ELECTRS_BIN="${ELECTRS_BIN:-$HOME/electrs/target/release/electrs}"
sudo install -m 755 "$ELECTRS_BIN" "$PREFIX/bin/electrs"

log "secrets"
if ! sudo test -f "$ETC/secrets.env"; then
	gen() { openssl rand -hex 24; }
	sudo tee "$ETC/secrets.env" >/dev/null <<EOF
BITCOIND_RPC_PASS=$(gen)
PG_CAPTAIND_PASS=$(gen)
PG_POSD_PASS=$(gen)
PG_RECEIPTS_PASS=$(gen)
EOF
	sudo chown root:scuttle "$ETC/secrets.env"
	sudo chmod 640 "$ETC/secrets.env"
fi
# shellcheck disable=SC1090
eval "$(sudo cat "$ETC/secrets.env")"

log "bitcoind (custom signet)"
# Challenge OP_TRUE: any block with valid proof of work is valid. The node
# does not listen for peers, so only this VM mines.
sudo tee "$DATA/bitcoind/bitcoin.conf" >/dev/null <<EOF
signet=1
server=1
txindex=1
listen=0
fallbackfee=0.0001
[signet]
signetchallenge=51
rpcport=$RPC_PORT
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=scuttle
rpcpassword=$BITCOIND_RPC_PASS
zmqpubrawblock=tcp://127.0.0.1:28332
zmqpubrawtx=tcp://127.0.0.1:28333
EOF
sudo chown scuttle:scuttle "$DATA/bitcoind/bitcoin.conf"
sudo chmod 600 "$DATA/bitcoind/bitcoin.conf"

sudo tee /etc/systemd/system/scuttle-bitcoind.service >/dev/null <<EOF
[Unit]
Description=scuttle signet bitcoind
After=network-online.target
[Service]
User=scuttle
ExecStart=/usr/local/bin/bitcoind -datadir=$DATA/bitcoind
Restart=on-failure
TimeoutStopSec=120
[Install]
WantedBy=multi-user.target
EOF

sudo tee "$PREFIX/bin/signet-mine" >/dev/null <<EOF
#!/usr/bin/env bash
# Mines N blocks (default 1) to the miner wallet.
set -euo pipefail
cli() { bitcoin-cli -datadir=$DATA/bitcoind -signet "\$@"; }
cli -rpcwait loadwallet miner >/dev/null 2>&1 || cli createwallet miner >/dev/null 2>&1 || true
addr=\$(cli -rpcwallet=miner getnewaddress)
for i in \$(seq "\${1:-1}"); do
	# A few fee-paying transactions in every block give bitcoind the fee
	# history it needs for estimatesmartfee. Lightning nodes refuse to open
	# channels without estimates. Fails harmlessly before coinbases mature.
	for rate in 2 3 5; do
		cli -rpcwallet=miner -named sendtoaddress address="\$addr" amount=0.0001 fee_rate=\$rate >/dev/null 2>&1 || true
	done
	# Signet's minimum difficulty needs about 5M hashes per block.
	cli generatetoaddress 1 "\$addr" 1000000000 >/dev/null
done
cli getblockcount
EOF
sudo chmod 755 "$PREFIX/bin/signet-mine"

sudo tee /etc/systemd/system/scuttle-miner.service >/dev/null <<EOF
[Unit]
Description=mine one signet block
Requires=scuttle-bitcoind.service
After=scuttle-bitcoind.service
[Service]
Type=oneshot
User=scuttle
ExecStart=$PREFIX/bin/signet-mine 1
EOF
sudo tee /etc/systemd/system/scuttle-miner.timer >/dev/null <<EOF
[Unit]
Description=a signet block every $BLOCK_INTERVAL_SECS seconds
[Timer]
OnActiveSec=$BLOCK_INTERVAL_SECS
OnUnitActiveSec=$BLOCK_INTERVAL_SECS
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-bitcoind.service
# Mature coinbases before anything spends them.
height=$(as_scuttle bitcoin-cli -datadir="$DATA/bitcoind" -signet -rpcwait getblockcount)
if [ "$height" -lt 110 ]; then
	as_scuttle "$PREFIX/bin/signet-mine" $((110 - height))
fi
sudo systemctl enable --now scuttle-miner.timer

log "postgres"
psql_su() { sudo -u postgres psql -v ON_ERROR_STOP=1 -q "$@"; }
ensure_role() {
	psql_su -c "DO \$\$ BEGIN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$1') THEN CREATE ROLE $1 LOGIN; END IF;
	END \$\$;"
	psql_su -c "ALTER ROLE $1 PASSWORD '$2';"
}
ensure_db() {
	psql_su -tAc "SELECT 1 FROM pg_database WHERE datname = '$1'" | grep -q 1 \
		|| psql_su -c "CREATE DATABASE $1 OWNER $2;"
}
ensure_role captaind "$PG_CAPTAIND_PASS"
ensure_role posd "$PG_POSD_PASS"
ensure_role posd_receipts "$PG_RECEIPTS_PASS"
ensure_db captaind captaind
ensure_db posd posd

log "CLN nodes (docker)"
sudo docker pull -q "$CLN_IMAGE" >/dev/null
cln_config() { # name, p2p port, grpc port, extra lines
	sudo tee "$DATA/$1/config" >/dev/null <<EOF
network=signet
alias=scuttle-$1
bitcoin-rpcconnect=127.0.0.1
bitcoin-rpcport=$RPC_PORT
bitcoin-rpcuser=scuttle
bitcoin-rpcpassword=$BITCOIND_RPC_PASS
addr=0.0.0.0:$2
grpc-port=$3
log-level=info
# A private signet has no fee history, so bitcoind never estimates fees.
force-feerates=2000
$4
EOF
	sudo chown scuttle:scuttle "$DATA/$1/config"
	sudo chmod 600 "$DATA/$1/config"
	sudo tee "/etc/systemd/system/scuttle-$1.service" >/dev/null <<EOF
[Unit]
Description=scuttle $1 lightningd
Requires=docker.service scuttle-bitcoind.service
After=docker.service scuttle-bitcoind.service
[Service]
ExecStartPre=-/usr/bin/docker rm -f scuttle-$1
ExecStart=/usr/bin/docker run --rm --name scuttle-$1 --net=host --user $(id -u scuttle):$(id -g scuttle) \\
	--mount type=bind,source=$DATA/$1,target=/data/.lightning \\
	$CLN_IMAGE --network=signet --lightning-dir=/data/.lightning
ExecStop=/usr/bin/docker stop -t 60 scuttle-$1
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
}
# The Ark server's node, with the hold invoice plugin.
cln_config cln-internal 9735 9736 "important-plugin=/plugins/hold
hold-grpc-port=9737"
# An ordinary Lightning node that plays the outside payer.
cln_config cln-external 9745 9746 ""
sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-cln-internal.service scuttle-cln-external.service
for i in $(seq 1 60); do
	sudo test -f "$DATA/cln-internal/signet/hold/ca.pem" && sudo test -f "$DATA/cln-internal/signet/ca.pem" && break
	sleep 2
done

log "captaind and watchmand"
fees_zero='[fees.board]
min_fee_sat = 0
base_fee_sat = 0
ppm = 0
[fees.offboard]
base_fee_sat = 0
fixed_additional_vb = 221
ppm_expiry_table = []
[fees.refresh]
base_fee_sat = 0
ppm_expiry_table = []
# The receive fee is zero, so a merchant gets the full amount on every rail.
[fees.lightning_receive]
base_fee_sat = 0
ppm = 0
[fees.lightning_send]
min_fee_sat = 0
base_fee_sat = 0
ppm_expiry_table = []'
pg_section() { # user, password, db
	printf '[postgres]\nhost = "127.0.0.1"\nport = 5432\nname = "%s"\nuser = "%s"\npassword = "%s"\nmax_connections = 10\n' "$3" "$1" "$2"
}
btc_section='[bitcoind]
url = "http://127.0.0.1:'$RPC_PORT'"
rpc_user = "scuttle"
rpc_pass = "'$BITCOIND_RPC_PASS'"'

sudo tee "$ETC/captaind.toml" >/dev/null <<EOF
data_dir = "$DATA/captaind"
network = "signet"
expiry_payouts = true
ln_receive_ark_address_hints = true
vtxo_lifetime = 4320
vtxo_exit_delta = 144
min_board_amount = "20000 sat"
required_board_confirmations = 1
min_trusted_confs = 1
round_interval = "10s"
round_submit_time = "2s"
round_sign_time = "2s"
htlc_expiry_delta = 40
htlc_send_expiry_delta = 1008
max_user_invoice_cltv_delta = 250
invoice_expiry = "48h"
receive_htlc_forward_timeout = "3min"
rpc_rich_errors = true
max_arkoor_fanout = 4
sync_manager_block_poll_interval = "100ms"
nursery_confirm_target_blocks = 6
otel_deployment_name = "scuttle-signet"
max_read_mailbox_items = 100
recovery_xpub_nb_keys = 100000
max_concurrent_xpub_recoveries = 1
nb_round_nonces = 8
max_round_participation_outputs = 4
round_forfeit_nonces_timeout = "30s"
offboard_session_timeout = "30s"
offboard_max_locked_percent = 25
offboard_check_interval = "1s"
offboard_acceptable_fee_rate_duration = "15m"
cln_reconnect_interval = "10s"
invoice_check_interval = "3s"
cln_xpay_timeout = "60s"
cln_xpay_max_retry_for = "5m"
invoice_check_base_delay = "10s"
max_invoice_check_delay = "10m"
invoice_poll_interval = "30s"
htlc_settlement_poll_interval = "60s"
track_all_base_delay = "1s"
max_track_all_delay = "60s"
ln_receive_anti_dos_required = false
round_status_attestation_required = false
forfeit_attestation_required = false
ln_max_fee_ppm = 900000
max_vtxo_exit_depth = 100

[[cln_array]]
uri = "https://localhost:9736"
priority = 10
server_cert_path = "$DATA/cln-internal/signet/ca.pem"
client_cert_path = "$DATA/cln-internal/signet/client.pem"
client_key_path = "$DATA/cln-internal/signet/client-key.pem"
hold_invoice.uri = "https://localhost:9737"
hold_invoice.server_cert_path = "$DATA/cln-internal/signet/hold/ca.pem"
hold_invoice.client_cert_path = "$DATA/cln-internal/signet/hold/client.pem"
hold_invoice.client_key_path = "$DATA/cln-internal/signet/hold/client-key.pem"

$fees_zero

[vtxopool]
vtxo_targets = [ "10000sat:10", "100000sat:10", "1000000sat:5" ]
vtxo_target_issue_threshold = 80
vtxo_lifetime = 4320
vtxo_pre_expiry = 2016
max_vtxo_exit_depth = 50

[fee_estimator]
update_interval = "1m"
history_duration = "60m"
fallback_fee_rate_fast = "5sat/vb"
fallback_fee_rate_regular = "2sat/vb"
fallback_fee_rate_slow = "1sat/vb"

[rpc]
public_address = "0.0.0.0:3535"
admin_address = "127.0.0.1:3536"
integration_address = "127.0.0.1:3537"

$(pg_section captaind "$PG_CAPTAIND_PASS" captaind)

$btc_section
EOF

# Swept funds go back to the miner's wallet: this is a test network.
SWEEP_ADDRESS=$(sudo grep -s '^sweep_address' "$ETC/watchmand.toml" | cut -d'"' -f2 || true)
[ -n "$SWEEP_ADDRESS" ] || SWEEP_ADDRESS=$(as_scuttle bitcoin-cli -datadir="$DATA/bitcoind" -signet -rpcwallet=miner getnewaddress sweep)
sudo tee "$ETC/watchmand.toml" >/dev/null <<EOF
data_dir = "$DATA/watchmand"
network = "signet"
sync_manager_block_poll_interval = "100ms"
htlc_settlement_poll_interval = "60s"
min_trusted_confs = 1
otel_deployment_name = "scuttle-signet"
admin_address = "127.0.0.1:4536"
sweep_address = "$SWEEP_ADDRESS"

[watchman]
reaction_interval = "10m"
sweep_interval = "2h"
progress_grace_period = 2
claim_chunksize = 20
incremental_relay_fee = "100 sat/kvb"
expiry_payout_max_fee_rate = "1000 sat/vb"
min_cpfp_amount = "10000 sat"

[fee_estimator]
update_interval = "1m"
history_duration = "60m"
fallback_fee_rate_fast = "5sat/vb"
fallback_fee_rate_regular = "2sat/vb"
fallback_fee_rate_slow = "1sat/vb"

$(pg_section captaind "$PG_CAPTAIND_PASS" captaind)

$btc_section
EOF
sudo chown root:scuttle "$ETC"/captaind.toml "$ETC"/watchmand.toml
sudo chmod 640 "$ETC"/captaind.toml "$ETC"/watchmand.toml

if ! sudo test -f "$DATA/captaind/mnemonic"; then
	as_scuttle "$PREFIX/bin/captaind" --config "$ETC/captaind.toml" create
fi
# watchmand derives its keys from the same seed.
sudo install -o scuttle -g scuttle -m 600 "$DATA/captaind/mnemonic" "$DATA/watchmand/mnemonic"

unit() { # name, description, exec, after
	sudo tee "/etc/systemd/system/scuttle-$1.service" >/dev/null <<EOF
[Unit]
Description=scuttle $2
After=$4
Requires=$4
[Service]
User=scuttle
Environment=RUST_LOG=info
ExecStart=$3
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
}
unit captaind "Ark server" "$PREFIX/bin/captaind --config $ETC/captaind.toml start" \
	"scuttle-bitcoind.service scuttle-cln-internal.service postgresql.service"
unit watchmand "Ark watchman" "$PREFIX/bin/watchmand --config $ETC/watchmand.toml start" \
	"scuttle-captaind.service"
sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-captaind.service scuttle-watchmand.service

# The delivery receipt view exists once captaind ran its migrations.
for i in $(seq 1 60); do
	psql_su -d captaind -tAc "SELECT 1 FROM pg_views WHERE viewname = 'v_arkoor_receive_delivery'" | grep -q 1 && break
	sleep 2
done
psql_su -d captaind -c "GRANT USAGE ON SCHEMA public TO posd_receipts; GRANT SELECT ON v_arkoor_receive_delivery TO posd_receipts;"

log "forwarder barkd"
sudo chmod 700 "$DATA/barkd"
# barkd writes its own auth token on first start.
unit barkd "forwarder barkd" "$PREFIX/bin/barkd --datadir $DATA/barkd --port 3000" "scuttle-captaind.service"
sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-barkd.service
for i in $(seq 1 30); do curl -sf http://127.0.0.1:3000/ping >/dev/null && break; sleep 1; done
BARKD_TOKEN=$(sudo cat "$DATA/barkd/auth_token")
if ! sudo test -f "$DATA/barkd/db.sqlite"; then
	curl -sf -X POST http://127.0.0.1:3000/api/v1/wallet/create \
		-H "Authorization: Bearer $BARKD_TOKEN" -H 'Content-Type: application/json' \
		-d "{\"ark_server\": \"http://127.0.0.1:3535\", \"network\": \"signet\",
			\"chain_source\": {\"bitcoind\": {\"bitcoind\": \"http://127.0.0.1:$RPC_PORT\",
			\"bitcoind_auth\": {\"user-pass\": {\"user\": \"scuttle\", \"pass\": \"$BITCOIND_RPC_PASS\"}}}}}" \
		>/dev/null
fi

log "posd"
sudo tee "$ETC/posd.toml" >/dev/null <<EOF
network = "signet"
ark_server_url = "http://127.0.0.1:3535"

[http]
listen = "0.0.0.0:3080"
public_url = "$PUBLIC_URL"

$(pg_section posd "$PG_POSD_PASS" posd)

[ark_server_postgres]
host = "127.0.0.1"
port = 5432
name = "captaind"
user = "posd_receipts"
password = "$PG_RECEIPTS_PASS"

[barkd]
url = "http://127.0.0.1:3000"
token = "$BARKD_TOKEN"

[bitcoind]
url = "http://127.0.0.1:$RPC_PORT"
rpc_user = "scuttle"
rpc_password = "$BITCOIND_RPC_PASS"
wallet = "posd"

[price]
# Signet coins have no price; a fixed one keeps the fiat keypad working.
fixed_btc_price = "62500000.00"
EOF
sudo chown root:scuttle "$ETC/posd.toml"
sudo chmod 640 "$ETC/posd.toml"
unit posd "point-of-sale service" "$PREFIX/bin/posd --config $ETC/posd.toml start" \
	"scuttle-captaind.service scuttle-barkd.service"
sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-posd.service

log "electrs (Esplora API)"
# A custom signet has its own network magic, which electrs cannot read from
# bitcoind's block files, so it imports blocks over RPC.
unit electrs "Esplora API" "$PREFIX/bin/electrs --network signet --jsonrpc-import \
	--db-dir $DATA/electrs --daemon-dir $DATA/bitcoind --daemon-rpc-addr 127.0.0.1:$RPC_PORT \
	--cookie scuttle:$BITCOIND_RPC_PASS --http-addr 127.0.0.1:3002 \
	--electrum-rpc-addr 127.0.0.1:50001 --monitoring-addr 127.0.0.1:4224 --cors *" \
	"scuttle-bitcoind.service"
sudo chmod 640 /etc/systemd/system/scuttle-electrs.service
sudo systemctl daemon-reload
sudo systemctl enable --now scuttle-electrs.service

log "status"
systemctl --no-pager --plain list-units 'scuttle-*' | head -20
echo "posd: $PUBLIC_URL   Ark server: port 3535   Esplora: 127.0.0.1:3002"
echo "Fund captaind next: contrib/deploy/signet/fund.sh"
