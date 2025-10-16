#!/bin/sh
set -e

HOSTNAME=$(hostname -s)
echo "Running CLN start command on host: ${HOSTNAME}"

echo "Using:"
export NETWORK=${NETWORK:=regtest}
echo " - network: ${NETWORK}"
export CLN_ALIAS=${CLN_ALIAS:=second.tech-${HOSTNAME}}
echo " - alias: ${CLN_ALIAS}"
export CLN_LOG_LEVEL=${CLN_LOG_LEVEL:=debug}
echo " - log.level: ${CLN_LOG_LEVEL}"
export CLN_GRPC_PORT=${CLN_GRPC_PORT:=9736}
echo " - grpc.port: ${CLN_GRPC_PORT}"
export CLN_GRPC_HOST=${CLN_GRPC_HOST:=0.0.0.0}
echo " - grpc.host: ${CLN_GRPC_HOST}"
export GRPC_PORT_HOLD=${HOLD_GRPC_PORT:=9988}
echo " - hold.gprc.port: ${HOLD_GRPC_PORT}"
export HOLD_GRPC_HOST=${HOLD_GRPC_HOST:=0.0.0.0}
echo " - hold.grpc.host: ${HOLD_GRPC_HOST}"
export BITCOIN_RPCCONNECT=${BITCOIN_RPCCONNECT:=bitcoind:18443}
echo " - bitcoin.rpcconnect: ${BITCOIN_RPCCONNECT}"
export BITCOIN_RPCUSER=${BITCOIN_RPCUSER:=second}
echo " - bitcoin.rpcuser: ${BITCOIN_RPCUSER}"
export BITCOIN_RPCPASSWORD=${BITCOIN_RPCPASSWORD:=ark}
echo " - bitcoin.rpcpassword: ***"
export CLN_BIND_ADDR=${CLN_BIND_ADDR:=0.0.0.0:9735}
echo " - bind.addr: ${CLN_BIND_ADDR}"
export CLN_ANNOUNCE_ADDR=${CLN_ANNOUNCE_ADDR:=${HOSTNAME}:9735}
echo " - announce.addr: ${CLN_ANNOUNCE_ADDR}"

echo "Booting"
lightningd --${NETWORK} --alias="${CLN_ALIAS}" --log-level=${CLN_LOG_LEVEL} \
	--grpc-port=${CLN_GRPC_PORT} --grpc-host=${CLN_GRPC_HOST} \
	--bitcoin-rpcconnect=${BITCOIN_RPCCONNECT} --bitcoin-rpcuser=${BITCOIN_RPCUSER} --bitcoin-rpcpassword=${BITCOIN_RPCPASSWORD} \
	--important-plugin=/hold/target/debug/hold --hold-grpc-host=${HOLD_GRPC_HOST} --hold-grpc-port=${HOLD_GRPC_PORT} \
	--bind-addr=${CLN_BIND_ADDR} --announce-addr=${CLN_ANNOUNCE_ADDR} &
LIGHTNINGD_PID=$!

WAIT_FILE="/root/.lightning/${NETWORK}/hold/ca.pem"
GEN_MARKER="/root/.lightning/${NETWORK}/hold/generation.done"

echo "Waiting for ${WAIT_FILE}..."
while [ ! -f "${WAIT_FILE}" ]; do
	sleep 1s
done

echo "Found file ${WAIT_FILE}"
if [ ! -f "${GEN_MARKER}" ]; then
	cat > /root/.lightning/${NETWORK}/v3.ext <<EOF
[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${HOSTNAME}
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF

	if [ "${HOSTNAME}" != "cln" ]; then
		rm /root/.lightning/${NETWORK}/server-key.pem
		rm /root/.lightning/${NETWORK}/server.pem
		echo "Generating custom CLN server certificate..."
		openssl ecparam -name prime256v1 -genkey -noout -out /root/.lightning/${NETWORK}/server-key.pem
		openssl req \
			-key /root/.lightning/${NETWORK}/server-key.pem -new \
			-out /root/.lightning/${NETWORK}/server.csr \
			-subj "/C=US/ST=California/L=SanFrancisco/O=Second/OU=Dev/CN=${HOSTNAME}"
		openssl x509 -req \
			-CA /root/.lightning/${NETWORK}/ca.pem -CAkey /root/.lightning/${NETWORK}/ca-key.pem \
			-in /root/.lightning/${NETWORK}/server.csr \
			-out /root/.lightning/${NETWORK}/server.pem \
			-days 3650 -CAcreateserial \
			-extfile /root/.lightning/${NETWORK}/v3.ext -extensions v3_req

		openssl x509 -in /root/.lightning/${NETWORK}/server.pem -text -noout
		openssl verify -CAfile /root/.lightning/${NETWORK}/ca.pem /root/.lightning/${NETWORK}/server.pem
	fi

	rm /root/.lightning/${NETWORK}/hold/server-key.pem
	rm /root/.lightning/${NETWORK}/hold/server.pem
	echo "Generating custom HOLD server certificate..."
	openssl ecparam -name prime256v1 -genkey -noout -out /root/.lightning/${NETWORK}/hold/server-key.pem
	openssl req \
		-key /root/.lightning/${NETWORK}/hold/server-key.pem -new \
		-out /root/.lightning/${NETWORK}/hold/server.csr \
		-subj "/C=US/ST=California/L=SanFrancisco/O=Second/OU=Dev/CN=${HOSTNAME}"
	openssl x509 -req \
		-CA /root/.lightning/${NETWORK}/hold/ca.pem -CAkey /root/.lightning/${NETWORK}/hold/ca-key.pem \
		-in /root/.lightning/${NETWORK}/hold/server.csr \
		-out /root/.lightning/${NETWORK}/hold/server.pem \
		-days 3650 -CAcreateserial \
		-extfile /root/.lightning/${NETWORK}/v3.ext -extensions v3_req

	openssl x509 -in /root/.lightning/${NETWORK}/hold/server.pem -text -noout
	openssl verify -CAfile /root/.lightning/${NETWORK}/hold/ca.pem /root/.lightning/${NETWORK}/hold/server.pem

	touch "${GEN_MARKER}"

	echo "Generation done rebooting"
	kill ${LIGHTNINGD_PID} || echo "Warning: lightningd might have exited before kill"
	sleep 1s

	echo "Booting"
	lightningd --${NETWORK} --alias="${CLN_ALIAS}" --log-level=${CLN_LOG_LEVEL} \
		--grpc-port=${CLN_GRPC_PORT} --grpc-host=${CLN_GRPC_HOST} \
		--bitcoin-rpcconnect=${BITCOIN_RPCCONNECT} --bitcoin-rpcuser=${BITCOIN_RPCUSER} --bitcoin-rpcpassword=${BITCOIN_RPCPASSWORD} \
		--important-plugin=/hold/target/debug/hold --hold-grpc-host=${HOLD_GRPC_HOST} --hold-grpc-port=${HOLD_GRPC_PORT} \
		--bind-addr=${CLN_BIND_ADDR} --announce-addr=${CLN_ANNOUNCE_ADDR}
else
	wait ${LIGHTNINGD_PID}
fi
