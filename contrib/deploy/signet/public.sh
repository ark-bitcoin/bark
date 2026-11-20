#!/usr/bin/env bash
# Publishes the signet deployment on the internet with Tailscale Funnel.
# Run after setup.sh, on a VM that has joined a tailnet with Funnel and
# HTTPS certificates enabled.
#
#   https://<host>/         posd: terminal PWA, API, Lightning address
#   https://<host>:8443     captaind gRPC, the Ark server address for wallets
#   https://<host>:10000    Esplora (electrs)
#   https://<host>/dev/     test faucet, mining and store wallets (devtools.py)
#
# Funnel allows only ports 443, 8443 and 10000. Everything else stays
# private: bitcoind, CLN, barkd, the admin RPCs and Postgres.
#
# gRPC clients require HTTP/2 negotiated in TLS (ALPN). Funnel's own TLS
# termination does not negotiate it and cannot proxy to an HTTP/2 backend,
# so :8443 is raw TCP to a local nginx that terminates TLS with the node's
# Tailscale certificate and passes gRPC to captaind.
set -euo pipefail

HOST=$(tailscale status --json | jq -r '.Self.DNSName' | sed 's/\.$//')
TLS=/etc/scuttle/tls
echo "publishing $HOST"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq nginx >/dev/null

# The certificate, renewed weekly. tailscale cert only fetches a new one
# when the current one is close to expiry.
sudo install -d -m 750 -o root -g www-data "$TLS"
sudo tee /usr/local/sbin/scuttle-renew-cert >/dev/null <<EOF
#!/bin/sh
set -e
tailscale cert --cert-file $TLS/$HOST.crt --key-file $TLS/$HOST.key $HOST
chgrp www-data $TLS/$HOST.crt $TLS/$HOST.key
chmod 640 $TLS/$HOST.crt $TLS/$HOST.key
systemctl reload nginx 2>/dev/null || true
EOF
sudo chmod 755 /usr/local/sbin/scuttle-renew-cert
sudo /usr/local/sbin/scuttle-renew-cert
sudo tee /etc/systemd/system/scuttle-renew-cert.service >/dev/null <<EOF
[Unit]
Description=renew the Tailscale TLS certificate for nginx
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/scuttle-renew-cert
EOF
sudo tee /etc/systemd/system/scuttle-renew-cert.timer >/dev/null <<EOF
[Unit]
Description=renew the Tailscale TLS certificate weekly
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
EOF

sudo rm -f /etc/nginx/sites-enabled/default
sudo tee /etc/nginx/sites-available/scuttle-grpc >/dev/null <<EOF
# The Ark server gRPC API, behind Funnel's raw TCP on :8443.
server {
	listen 127.0.0.1:8444 ssl;
	http2 on;
	server_name $HOST;
	ssl_certificate $TLS/$HOST.crt;
	ssl_certificate_key $TLS/$HOST.key;
	location / {
		grpc_pass grpc://127.0.0.1:3535;
		# Mailbox and round streams stay open.
		grpc_read_timeout 1h;
		grpc_send_timeout 1h;
	}
}
EOF
sudo ln -sf /etc/nginx/sites-available/scuttle-grpc /etc/nginx/sites-enabled/scuttle-grpc
sudo nginx -t
sudo systemctl daemon-reload
sudo systemctl enable --now nginx scuttle-renew-cert.timer
sudo systemctl reload nginx

# Test helpers for people without access to the VM.
sudo install -m 755 "$(dirname "$0")/devtools.py" /opt/scuttle/bin/devtools
sudo tee /etc/systemd/system/scuttle-devtools.service >/dev/null <<UNIT
[Unit]
Description=scuttle signet test faucet and miner
After=scuttle-bitcoind.service
[Service]
User=scuttle
ExecStart=/usr/bin/python3 /opt/scuttle/bin/devtools
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable scuttle-devtools.service
sudo systemctl restart scuttle-devtools.service

sudo tailscale funnel --bg --https=443 http://127.0.0.1:3080 >/dev/null
sudo tailscale funnel --bg --https=443 --set-path=/dev http://127.0.0.1:3090 >/dev/null
sudo tailscale funnel --bg --tcp=8443 tcp://127.0.0.1:8444 >/dev/null
sudo tailscale funnel --bg --https=10000 http://127.0.0.1:3002 >/dev/null
sudo tailscale funnel status

echo
echo "posd public_url must be https://$HOST. If it is not, rerun:"
echo "  PUBLIC_URL=https://$HOST ./contrib/deploy/signet/setup.sh && sudo systemctl restart scuttle-posd"
