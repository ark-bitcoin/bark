#!/bin/sh
set -e

lightningd --regtest --log-level=debug --grpc-host=0.0.0.0 \
  --bitcoin-datadir=/root/.bitcoin --bitcoin-rpcconnect=bitcoind:18443 --bitcoin-rpcuser=second --bitcoin-rpcpassword=ark \
  --important-plugin=/hold/target/debug/hold --hold-grpc-host=0.0.0.0 --hold-grpc-port=9988 &
LIGHTNINGD_PID=$!

WAIT_FILE="/root/.lightning/regtest/hold/ca.pem"
GEN_MARKER="/root/.lightning/regtest/hold/generation.done"

echo "Waiting for ${WAIT_FILE}..."
while [ ! -f "${WAIT_FILE}" ]; do
  sleep 1s
done

echo "Found file ${WAIT_FILE}"
if [ ! -f "${GEN_MARKER}" ]; then
#  rm /root/.lightning/regtest/hold/ca-key.pem
#  rm /root/.lightning/regtest/hold/ca.pem
  rm /root/.lightning/regtest/hold/server-key.pem
  rm /root/.lightning/regtest/hold/server.pem
#  rm /root/.lightning/regtest/hold/client-key.pem
#  rm /root/.lightning/regtest/hold/client.pem
#  cp /root/.lightning/regtest/*.pem /root/.lightning/regtest/hold/
  echo "Generating custom server certificate..."
  cat > /root/.lightning/regtest/hold/v3.ext <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = cln
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

  openssl ecparam -name prime256v1 -genkey -noout -out /root/.lightning/regtest/hold/server-key.pem
  openssl req \
    -key /root/.lightning/regtest/hold/server-key.pem -new \
    -out /root/.lightning/regtest/hold/server.csr \
    -subj "/C=US/ST=California/L=SanFrancisco/O=Second/OU=Dev/CN=cln"
  openssl x509 -req \
    -CA /root/.lightning/regtest/hold/ca.pem -CAkey /root/.lightning/regtest/hold/ca-key.pem \
    -in /root/.lightning/regtest/hold/server.csr \
    -out /root/.lightning/regtest/hold/server.pem \
    -days 3650 -CAcreateserial \
    -extfile /root/.lightning/regtest/hold/v3.ext -extensions v3_req

  openssl x509 -in /root/.lightning/regtest/hold/server.pem -text -noout
  openssl verify -CAfile /root/.lightning/regtest/hold/ca.pem /root/.lightning/regtest/hold/server.pem

  touch "${GEN_MARKER}"

  echo "Generation done rebooting"
  kill ${LIGHTNINGD_PID} || echo "Warning: lightningd might have exited before kill"
  sleep 1s

  echo "Booting"
  lightningd --regtest --log-level=debug --grpc-host=0.0.0.0 \
    --bitcoin-datadir=/root/.bitcoin --bitcoin-rpcconnect=bitcoind:18443 --bitcoin-rpcuser=second --bitcoin-rpcpassword=ark \
    --important-plugin=/hold/target/debug/hold --hold-grpc-host=0.0.0.0 --hold-grpc-port=9988
else
  wait ${LIGHTNINGD_PID}
fi
