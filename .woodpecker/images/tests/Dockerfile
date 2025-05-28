FROM docker.io/ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	wget \
	curl \
	git \
	xz-utils \
	build-essential \
	cmake \
	clang \
	make \
	pkg-config \
	ripgrep \
	libsodium-dev \
	libssl-dev \
	libclang-dev \
	sqlite3 \
	libsqlite3-dev \
	libpq5 \
	postgresql \
	postgresql-contrib \
	lzma-dev \
	protobuf-compiler \
	jq \
	mingw-w64 \
	gcc-mingw-w64 \
	llvm \
	libxml2-dev \
	python3 \
	libpq-dev \
	sudo

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN_VERSION=1.77 \
	BITCOIN_VERSION=29.0 \
	CLN_VERSION=25.02 \
	MACOS_SDK_VERSION=15.1 \
	ELECTRS_HASH=a9a39b1616591fb08514fba4df1c1ca11b24a500 \
	PATH=/root/.cargo/bin:/usr/lib/postgresql/16/bin:${PATH} \
	ZIG_VERSION=0.13.0

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

RUN service postgresql start && \
	sudo -u postgres psql -c "ALTER USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION} && \
	rustup target add x86_64-pc-windows-gnu && \
	rustup target add aarch64-unknown-linux-gnu && \
	rustup target add armv7-unknown-linux-gnueabihf && \
	rustup target add x86_64-apple-darwin && \
	rustup target add aarch64-apple-darwin
RUN echo "Installing bitcoin core in /bitcoin/${BITCOIN_VERSION}/bin/" && \
	mkdir /bitcoin && \
	cd /bitcoin && \
	wget https://bitcoincore.org/bin/bitcoin-core-${BITCOIN_VERSION}/bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
	tar xvzf bitcoin-${BITCOIN_VERSION}-x86_64-linux-gnu.tar.gz && \
	mv bitcoin-${BITCOIN_VERSION} ${BITCOIN_VERSION} && \
	cp /bitcoin/${BITCOIN_VERSION}/bin/bitcoin-cli /usr/bin/bitcoin-cli
RUN echo "Installing c-lightning in /lightning/${CLN_VERSION}/bin/" && \
	mkdir /lightning && \
	cd /lightning && \
	wget https://github.com/ElementsProject/lightning/releases/download/v${CLN_VERSION}/clightning-v${CLN_VERSION}-Ubuntu-24.04-amd64.tar.xz && \
	mkdir ${CLN_VERSION} && \
	tar -xvf clightning-v${CLN_VERSION}-Ubuntu-24.04-amd64.tar.xz -C ./${CLN_VERSION} --strip-components=2
RUN echo "Installing c-lightning hold invoice plugin in /hold/" && \
	mkdir /plugins && \
    git clone https://github.com/BoltzExchange/hold.git && \
	cd hold && \
	git checkout v0.3.0 && \
	cargo build && \
	cp /hold/target/debug/hold /plugins && \
	chown root:root /plugins/hold
RUN cd /root/ && \
	git clone https://github.com/tpoechtrager/osxcross.git && \
	cd /root/osxcross/tarballs/ && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/MacOSX${MACOS_SDK_VERSION}.sdk.tar.xz && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/sha256sum.txt && \
	cd /root/osxcross/ && \
	TARGET_DIR=/usr/local/osxcross SDK_VERSION=${MACOS_SDK_VERSION} UNATTENDED=1 ./build.sh && \
	export PATH=$PATH:/usr/local/osxcross/bin
RUN echo "Installing sccache"
RUN cargo install --locked sccache
RUN echo "Installing just"
RUN cargo install --locked just
RUN echo "Installing cargo-llvm-cov"
RUN cargo install --locked cargo-llvm-cov
RUN mkdir -p /root/.cargo && \
	echo '[build]\nrustc-wrapper = "sccache"\n[target.x86_64-pc-windows-gnu]\nlinker = "x86_64-w64-mingw32-gcc"\n[target.i686-pc-windows-gnu]\nlinker = "i686-w64-mingw32-gcc"\n[target.x86_64-apple-darwin]\nlinker = "/usr/local/osxcross/bin/x86_64-apple-darwin24.1-clang"\nar = "/usr/local/osxcross/bin/x86_64-apple-darwin24.1-ar"\n[target.aarch64-apple-darwin]\nlinker = "/usr/local/osxcross/bin/aarch64-apple-darwin24.1-clang"\nar = "/usr/local/osxcross/bin/aarch64-apple-darwin24.1-ar"\n' > /root/.cargo/config.toml
RUN cat /root/.cargo/config.toml
RUN echo "Installing Blockstream's electrs..." && \
	cd /root && \
	git clone -b submit-tx-package https://github.com/stevenroose/electrs.git --depth 1 && \
	cd electrs && \
	git fetch --depth 1 origin ${ELECTRS_HASH} && \
	cargo install --locked --path .
RUN echo "pre-build bark" && \
	cd /root && \
	wget https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	tar -xJf zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	ln -s /root/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/bin/ && \
	cargo install cargo-zigbuild && \
	export SDKROOT=/usr/local/osxcross/SDK/MacOSX${MACOS_SDK_VERSION}.sdk && \
	git clone https://codeberg.org/ark-bitcoin/bark.git && \
	cd bark && \
	cargo build --workspace && \
	cargo llvm-cov --workspace --exclude ark-testing --html && \
	cargo install --locked --path bark && \
	cargo install --locked --path aspd && \
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark/Cargo.toml && \
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark/Cargo.toml
RUN rm -rf /root/bark
RUN echo "Done"
