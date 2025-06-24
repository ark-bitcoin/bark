FROM elementsproject/lightningd:v25.02.2

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	git \
	curl \
	gcc \
	libpq-dev \
	libsqlite3-dev \
	protobuf-compiler \
	dos2unix

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN_VERSION=1.82 \
	CLN_VERSION=25.02.2 \
	PATH=/root/.cargo/bin:${PATH} \
	NETWORK=regtest \
	BITCOIN_RPCCONNECT=bitcoind:18443 \
	BITCOIN_RPCUSER=second \
	BITCOIN_RPCPASSWORD=ark

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION}

RUN echo "Installing c-lightning hold invoice plugin in /hold/" && \
	git clone https://github.com/BoltzExchange/hold.git && \
	cd hold && \
	git checkout v0.2.2 && \
	cargo build && \
	chown root:root /hold/target/debug/hold && \
	chmod a+x /hold/target/debug/hold

RUN mkdir -p /root/cln/
ADD ./contrib/docker/cln_start.sh /root/cln/start.sh

RUN chmod a+x /root/cln/start.sh && \
	dos2unix /root/cln/start.sh

EXPOSE 9988