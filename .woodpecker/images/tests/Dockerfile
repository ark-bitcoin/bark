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
	sudo \
	&& rm -rf /var/lib/apt/lists/*

ENV RUST_BACKTRACE=1 \
	DEBIAN_FRONTEND=noninteractive \
	RUSTUP_TOOLCHAIN_VERSION=1.88 \
	MACOS_SDK_VERSION=15.4 \
	MACOS_DARWIN_VERSION=24.4 \
	PATH=/root/.cargo/bin:/usr/lib/postgresql/16/bin:${PATH} \
	ZIG_VERSION=0.13.0 \
	NIX_PATH=/nix/var/nix/profiles/per-user/root/channels \
	NIX_PROFILES="/nix/var/nix/profiles/default /root/.nix-profile" \
	POSTGRES_USER=postgres \
	POSTGRES_PASSWORD=postgres

RUN mkdir -p /nix && \
	groupadd -r nixbld -g 30000 && \
	for i in $(seq 1 32); do \
		useradd -r -u $((30000 + i)) -g nixbld -G nixbld -M -N nixbld$i; \
	done && \
	chown root:nixbld /nix

ENV PATH="/root/.nix-profile/bin:/root/.nix-profile/sbin:/root/.nix-profile/lib:/nix/var/nix/profiles/default/bin:$PATH"
RUN bash -c '\
  curl -L https://nixos.org/nix/install | bash -s -- --daemon && \
  . /etc/profile.d/nix.sh && \
  nix-env --version \
'

RUN echo "clone bark" && \
	cd /root && \
	git clone -b master https://codeberg.org/ark-bitcoin/bark.git

RUN echo "build nix devShell" && \
	. /etc/profile.d/nix.sh && \
	nix --extra-experimental-features 'nix-command flakes' develop /root/bark#default --command bash -c "\
		echo Flake devShell ready"
RUN echo "experimental-features = nix-command flakes" >> /etc/nix/nix.conf
RUN cat /etc/nix/nix.conf

RUN service postgresql start && \
	sudo -u postgres psql -c "ALTER USER ${POSTGRES_USER} WITH PASSWORD '${POSTGRES_PASSWORD}';" && \
	service postgresql stop

RUN echo "build bark" && \
	. /etc/profile.d/nix.sh && \
	cd /root/bark && \
	nix develop /root/bark#default --command bash -c "\
		cargo build --workspace && \
		cargo llvm-cov --workspace --exclude ark-testing --html && \
		cargo install --locked --path bark && \
		cargo install --locked --path server"

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION} && \
	rustup target add x86_64-pc-windows-gnu && \
	rustup target add x86_64-unknown-linux-gnu && \
	rustup target add aarch64-unknown-linux-gnu && \
	rustup target add armv7-unknown-linux-gnueabihf && \
	rustup target add x86_64-apple-darwin && \
	rustup target add aarch64-apple-darwin
RUN cd /root/ && \
	git clone https://github.com/tpoechtrager/osxcross.git && \
	cd /root/osxcross/tarballs/ && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/MacOSX${MACOS_SDK_VERSION}.sdk.tar.xz && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/sha256sum.txt && \
	cd /root/osxcross/ && \
	TARGET_DIR=/usr/local/osxcross SDK_VERSION=${MACOS_SDK_VERSION} UNATTENDED=1 ./build.sh && \
	export PATH=$PATH:/usr/local/osxcross/bin && \
	ls -alh /usr/local/osxcross/bin
RUN echo "Installing sccache"
RUN cargo install --locked sccache
RUN echo "Installing just"
RUN cargo install --locked just
RUN mkdir -p /root/.cargo && \
	echo '[build]\nrustc-wrapper = "sccache"\n[target.x86_64-pc-windows-gnu]\nlinker = "x86_64-w64-mingw32-gcc"\n[target.i686-pc-windows-gnu]\nlinker = "i686-w64-mingw32-gcc"\n[target.x86_64-apple-darwin]\nlinker = "/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-clang"\nar = "/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-ar"\n[target.aarch64-apple-darwin]\nlinker = "/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-clang"\nar = "/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-ar"\n' > /root/.cargo/config.toml
RUN cat /root/.cargo/config.toml
RUN echo "pre-build bark" && \
	cd /root && \
	wget https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	tar -xJf zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	ln -s /root/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/bin/ && \
	cargo install cargo-zigbuild && \
	export SDKROOT=/usr/local/osxcross/SDK/MacOSX${MACOS_SDK_VERSION}.sdk && \
	cd /root/bark && \
	RUSTFLAGS="-C debuginfo=2" cargo build --release --target x86_64-unknown-linux-gnu --locked --manifest-path server/Cargo.toml && \
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark/Cargo.toml && \
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark/Cargo.toml
RUN rm -rf /root/bark
RUN echo "Done"
