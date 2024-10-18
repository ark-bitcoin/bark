FROM ubuntu:24.04 as builder

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	wget \
	curl \
	git \
	xz-utils \
	build-essential \
	cmake \
	clang

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN=1.77.2 \
	PATH=/root/.cargo/bin:${PATH}

# Installs the following components
# * rustup Rust toolchains:
#   - 1.77.2
# * bitcoin core binaries in /bitcoin/<ver>/bin/
#   - 28.0-rc2
#   - 27.1
# * c-lightning binaries in /lightning/<ver>/bin
#   - 24.05
# * Blockstream's electrs
#   - commit 16321d4a7523b98c199d02ce793d13dee79dedfa

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none && \
	echo "Installing Rust toolchains..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN} && \
	echo "Installing bitcoin..." && \
	mkdir /bitcoin && cd /bitcoin && \
	echo "Installing bitcoin core v28.0-rc2..." && \
	wget https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-linux-gnu.tar.gz && \
	tar xvzf bitcoin-28.0-x86_64-linux-gnu.tar.gz && mv bitcoin-28.0 28.0 && \
	echo "Installing bitcoin core v27.1..." && \
	wget https://bitcoincore.org/bin/bitcoin-core-27.1/bitcoin-27.1-x86_64-linux-gnu.tar.gz && \
	tar xvzf bitcoin-27.1-x86_64-linux-gnu.tar.gz && mv bitcoin-27.1 27.1 && \
	echo "Installing lightning..." && \
	mkdir /lightning && cd /lightning && \
	echo "Installing c-lightning v24.05..." && \
	wget https://github.com/ElementsProject/lightning/releases/download/v24.05/clightning-v24.05-Ubuntu-24.04.tar.xz && \
	mkdir 24.05 && tar -xvf clightning-v24.05-Ubuntu-24.04.tar.xz -C ./24.05 --strip-components=2 && \
	echo "Installing electrs..." && cd /root && \
	git clone https://github.com/Blockstream/electrs.git --depth 1 && cd electrs && \
	git fetch --depth 1 origin 16321d4a7523b98c199d02ce793d13dee79dedfa && \
	cargo install --locked --path . && \
	echo "Done"


FROM debian:trixie-slim

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

ENV RUST_BACKTRACE=1 \
	ROCKSDB_LIB_DIR=/usr/lib/x86_64-linux-gnu \
	RUSTUP_TOOLCHAIN=1.77.2 \
	PATH=/root/.cargo/bin:${PATH}

COPY --from=builder /bitcoin/28.0/bin/bitcoin-cli     /usr/bin/bitcoin-cli
COPY --from=builder /bitcoin/28.0/bin/bitcoind        /bitcoin/28.0/bin/bitcoind
COPY --from=builder /bitcoin/27.1/bin/bitcoind        /bitcoin/27.1/bin/bitcoind
COPY --from=builder /lightning                        /lightning
COPY --from=builder /root/.cargo/bin                  /root/.cargo/bin
