FROM docker.io/ubuntu:25.04

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
	zlib1g-dev \
	sqlite3 \
	libsqlite3-dev \
	libpq5 \
	postgresql \
	postgresql-contrib \
	protobuf-compiler \
	jq \
	mingw-w64 \
	gcc-mingw-w64 \
	llvm \
	libxml2-dev \
	python3 \
	libpq-dev \
	sudo \
	podman \
	&& rm -rf /var/lib/apt/lists/*

ENV RUST_BACKTRACE=1 \
	DEBIAN_FRONTEND=noninteractive \
	PATH=/home/nixuser/.cargo/bin:/home/nixuser/.nix-profile/bin:/home/nixuser/.nix-profile/sbin:/home/nixuser/.nix-profile/lib:/nix/var/nix/profiles/default/bin:$PATH \
	NIX_PATH=/nix/var/nix/profiles/per-user/nixuser/channels \
	NIX_PROFILES="/nix/var/nix/profiles/default /nixuser/.nix-profile" \
	RUSTUP_TOOLCHAIN_VERSION=1.90 \
	MACOS_SDK_VERSION=15.4 \
	MACOS_DARWIN_VERSION=24.4 \
	ZIG_VERSION=0.13.0

RUN mkdir -p /nix && \
	groupadd -r nixbld -g 30000 && \
	for i in $(seq 1 32); do \
		useradd -r -u $((30000 + i)) -g nixbld -G nixbld -M -N nixbld$i; \
	done

RUN useradd -m -s /bin/bash -g nixbld -G nixbld nixuser
RUN echo "nixuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/nixuser && chmod 0440 /etc/sudoers.d/nixuser
USER nixuser
WORKDIR /home/nixuser

RUN sudo chown -R nixuser:nixbld /nix

RUN mkdir -p ~/.config/containers && \
	echo '{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{"":[{"type":"insecureAcceptAnything"}]},"docker-archive":{"":[{"type":"insecureAcceptAnything"}]}}}' > ~/.config/containers/policy.json

RUN curl -L https://nixos.org/nix/install | bash -s -- --daemon && \
	sudo chown -R nixuser:nixbld /nix && \
	. /etc/profile.d/nix.sh && \
	nix-env --version

RUN mkdir -p ~/.config/nix && \
	echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

RUN mkdir -p /nix/var/nix/profiles/per-user/nixuser/channels

COPY Xcode_16.3.xip /tmp/
RUN echo "xcode prep work"  && \
	. /etc/profile.d/nix.sh && \
	cd /tmp && \
	nix-shell -p xar pbzx cpio rcodesign --command "\
		xar -xf Xcode_16.3.xip && \
		pbzx -n Content | cpio -i && \
		rcodesign verify Xcode.app/Contents/MacOS/Xcode" && \
	nix-store --add-fixed --recursive sha256 Xcode.app && \
	sudo rm Xcode_16.3.xip Content Metadata && \
	sudo rm -rf Xcode.app

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION} && \
	rustup target add x86_64-pc-windows-gnu && \
	rustup target add x86_64-unknown-linux-gnu && \
	rustup target add aarch64-unknown-linux-gnu && \
	rustup target add armv7-unknown-linux-gnueabihf && \
	rustup target add x86_64-apple-darwin && \
	rustup target add aarch64-apple-darwin

RUN cd /tmp/ && \
	git clone https://github.com/tpoechtrager/osxcross.git && \
	cd /tmp/osxcross/tarballs/ && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/MacOSX${MACOS_SDK_VERSION}.sdk.tar.xz && \
	wget https://github.com/joseluisq/macosx-sdks/releases/download/${MACOS_SDK_VERSION}/sha256sum.txt && \
	cd /tmp/osxcross/ && \
	sudo mkdir -p /usr/local/osxcross && \
	sudo chown -R nixuser:nixbld /usr/local/osxcross && \
	TARGET_DIR=/usr/local/osxcross SDK_VERSION=${MACOS_SDK_VERSION} UNATTENDED=1 ./build.sh && \
	export PATH=$PATH:/usr/local/osxcross/bin && \
	ls -alh /usr/local/osxcross/bin

#RUN echo "Installing sccache"
#RUN cargo install --locked sccache
RUN echo "Installing just"
RUN cargo install --locked just
#RUN mkdir -p /home/nixuser/.cargo && \
#	echo "[build]\nrustc-wrapper = \"sccache\"\n[target.x86_64-pc-windows-gnu]\nlinker = \"x86_64-w64-mingw32-gcc\"\n[target.i686-pc-windows-gnu]\nlinker = \"i686-w64-mingw32-gcc\"\n[target.x86_64-apple-darwin]\nlinker = \"/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-clang\"\nar = \"/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-ar\"\n[target.aarch64-apple-darwin]\nlinker = \"/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-clang\"\nar = \"/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-ar\"\n" > /home/nixuser/.cargo/config.toml
RUN mkdir -p /home/nixuser/.cargo && \
	echo "[target.x86_64-pc-windows-gnu]\nlinker = \"x86_64-w64-mingw32-gcc\"\n[target.i686-pc-windows-gnu]\nlinker = \"i686-w64-mingw32-gcc\"\n[target.x86_64-apple-darwin]\nlinker = \"/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-clang\"\nar = \"/usr/local/osxcross/bin/x86_64-apple-darwin${MACOS_DARWIN_VERSION}-ar\"\n[target.aarch64-apple-darwin]\nlinker = \"/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-clang\"\nar = \"/usr/local/osxcross/bin/aarch64-apple-darwin${MACOS_DARWIN_VERSION}-ar\"\n" > /home/nixuser/.cargo/config.toml
RUN cat /home/nixuser/.cargo/config.toml

RUN echo "clone bark" && \
	git clone -b hold-plugin-upgrade https://gitlab.com/ark-bitcoin/bark.git

RUN echo "pre-build bark" && \
	cd /tmp && \
	wget https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	tar -xJf zig-linux-x86_64-${ZIG_VERSION}.tar.xz && \
	sudo ln -s /tmp/zig-linux-x86_64-${ZIG_VERSION}/zig /usr/bin/ && \
	cargo install cargo-zigbuild && \
	export SDKROOT=/usr/local/osxcross/SDK/MacOSX${MACOS_SDK_VERSION}.sdk && \
	cd ~/bark && \
	RUSTFLAGS="-C debuginfo=2" cargo build --release --target x86_64-unknown-linux-gnu --locked --manifest-path server/Cargo.toml && \
	cargo build --release --target x86_64-unknown-linux-gnu         --locked --manifest-path bark/Cargo.toml && \
	cargo build --release --target x86_64-pc-windows-gnu            --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-unknown-linux-gnu     --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target armv7-unknown-linux-gnueabihf --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target x86_64-apple-darwin           --locked --manifest-path bark/Cargo.toml && \
	cargo zigbuild --release --target aarch64-apple-darwin          --locked --manifest-path bark/Cargo.toml

RUN echo "build nix devShell" && \
	. /etc/profile.d/nix.sh && \
	cd ~/bark && \
	nix develop .#default --command bash -c "echo Flake devShell ready"

RUN echo "build bark" && \
	. /etc/profile.d/nix.sh && \
	cd ~/bark && \
	nix develop .#default --command bash -c "\
		cargo build --workspace && \
		cargo install --locked --path bark-cli && \
		cargo install --locked --path server && \
		cargo run --example dump-sqlite-schema && \
		cargo run --example dump-server-postgres-schema"

RUN rm -rf /tmp/bark
RUN echo "Done"
