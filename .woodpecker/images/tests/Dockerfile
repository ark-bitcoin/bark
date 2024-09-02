FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	build-essential \
	pkg-config \
	curl \
	wget \
	cmake \
	git \
	clang \
	libssl-dev \
	libclang-dev \
	libsqlite3-dev \
	libpq5 \
	librocksdb-dev \
	protobuf-compiler

ENV BITCOIND_VERSION=27.1 \
	LIGHTNINGD_VERSION=24.05 \
	RUST_VERSION=1.77.2 \
	RUST_BACKTRACE=1 \
	ROCKSDB_LIB_DIR=/usr/lib/x86_64-linux-gnu \
	PATH=/root/.cargo/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none && \
	rustup toolchain install ${RUST_VERSION} && \
	wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIND_VERSION}/bitcoin-${BITCOIND_VERSION}-x86_64-linux-gnu.tar.gz && \
	tar xvzf bitcoin-$BITCOIND_VERSION-x86_64-linux-gnu.tar.gz && \
	install -m 0755 -o root -g root -t /usr/local/bin bitcoin-${BITCOIND_VERSION}/bin/* && \
	wget https://github.com/ElementsProject/lightning/releases/download/v${LIGHTNINGD_VERSION}/clightning-v${LIGHTNINGD_VERSION}-Ubuntu-24.04.tar.xz && \
	tar -xvf clightning-v${LIGHTNINGD_VERSION}-Ubuntu-24.04.tar.xz -C /usr/local --strip-components=2

