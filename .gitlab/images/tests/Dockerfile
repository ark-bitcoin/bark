FROM docker.io/ubuntu:25.04

# All cargo builds run inside the nix devShells, which provide their own
# toolchain, protobuf, sqlite, postgres etc. The packages here only cover
# what runs outside those shells: the justfile release recipes (just, jq,
# cargo for `cargo metadata`), registry pushes (podman, buildah, passt),
# repo mirroring (openssh-client), CI helper scripts (python3, ripgrep) and
# the nix install itself (curl, xz-utils).
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	wget \
	curl \
	git \
	xz-utils \
	build-essential \
	pkg-config \
	ripgrep \
	jq \
	just \
	python3 \
	sudo \
	podman \
	buildah \
	gnupg2 \
	openssh-client \
	qemu-user-static \
	passt \
	&& rm -rf /var/lib/apt/lists/*

COPY wakemeops.gpg /etc/apt/trusted.gpg.d/
RUN cat /etc/apt/trusted.gpg.d/wakemeops.gpg | gpg --dearmor > /etc/apt/trusted.gpg.d/wakemeops-keyring.gpg && \
	echo "deb [signed-by=/etc/apt/trusted.gpg.d/wakemeops-keyring.gpg] http://deb.wakemeops.com/wakemeops stable dev devops" > /etc/apt/sources.list.d/wakemeops.list && \
	apt-get update && \
	apt-get install -y --no-install-recommends glab && \
	rm -rf /var/lib/apt/lists/*

ENV RUST_BACKTRACE=full \
	RUSTUP_TOOLCHAIN_VERSION=1.90 \
	CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_DEBUG=true \
	DEBIAN_FRONTEND=noninteractive \
	PATH=/home/nixuser/.cargo/bin:/home/nixuser/.nix-profile/bin:/home/nixuser/.nix-profile/sbin:/home/nixuser/.nix-profile/lib:/nix/var/nix/profiles/default/bin:$PATH \
	NIX_PATH=/nix/var/nix/profiles/per-user/nixuser/channels \
	NIX_PROFILES="/nix/var/nix/profiles/default /nixuser/.nix-profile"
RUN echo '* soft nproc 65535' >> /etc/security/limits.conf && \
	echo '* hard nproc 65535' >> /etc/security/limits.conf

RUN mkdir -p /nix && \
	groupadd -r nixbld -g 30000 && \
	for i in $(seq 1 32); do \
		useradd -r -u $((30000 + i)) -g nixbld -G nixbld -M -N nixbld$i; \
	done

RUN useradd -m -s /bin/bash -g nixbld -G nixbld nixuser
RUN echo "nixuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/nixuser && chmod 0440 /etc/sudoers.d/nixuser
USER nixuser
WORKDIR /home/nixuser

# When changing this path one should also change SWAGGER_UI_DOWNLOAD_URL in
# .gitlab-ci.yml and nix/ci-shell.nix.
RUN mkdir -p /home/nixuser/assets/swagger-ui && \
	wget -O /home/nixuser/assets/swagger-ui/v5.30.2.zip https://github.com/swagger-api/swagger-ui/archive/refs/tags/v5.30.2.zip

RUN mkdir -p ~/.config/containers && \
	echo '{"default":[{"type":"insecureAcceptAnything"}],"transports":{"docker":{"":[{"type":"insecureAcceptAnything"}]},"docker-archive":{"":[{"type":"insecureAcceptAnything"}]}}}' > ~/.config/containers/policy.json
RUN sudo mkdir -p /etc/containers && \
	echo '[storage]'      | sudo tee    /etc/containers/storage.conf && \
	echo 'driver = "vfs"' | sudo tee -a /etc/containers/storage.conf
RUN curl -L https://nixos.org/nix/install | bash -s -- --daemon && \
	sudo chown -R nixuser:nixbld /nix && \
	. /etc/profile.d/nix.sh && \
	nix-env --version

RUN mkdir -p ~/.config/nix && \
	echo "experimental-features = nix-command flakes" >> ~/.config/nix/nix.conf

RUN mkdir -p /nix/var/nix/profiles/per-user/nixuser/channels

# The justfile resolves CARGO_TARGET with `cargo metadata` at startup, so a
# cargo binary is needed even for recipes that only drive nix (the release
# recipes run outside the nix shells). Everything that actually compiles
# runs inside the nix shells with their own toolchain and sccache.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none

RUN echo "Installing Rust toolchain version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION}

# Normalize source paths in rustc metadata so this pre-built target/
# (at /home/nixuser/bark) is fingerprint-compatible with what CI produces
# from $CI_PROJECT_DIR (typically /builds/ark-bitcoin/bark). Uses
# CARGO_BUILD_RUSTFLAGS rather than RUSTFLAGS so wasm builds still pick
# up target.wasm32-unknown-unknown.rustflags from .cargo/config.toml
# (env RUSTFLAGS would override that and drop the getrandom cfg).
# Local devs never set these vars, so their builds are unaffected. Keep
# in sync with .gitlab-ci.yml.
ENV CARGO_BUILD_RUSTFLAGS="--remap-path-prefix=/builds/ark-bitcoin/bark=/build --remap-path-prefix=/home/nixuser/bark=/build"
ENV CARGO_INCREMENTAL=0
ENV NIX_CONFIG="accept-flake-config = true"
RUN echo "extra-trusted-users = nixuser" | sudo tee -a /etc/nix/nix.conf && \
	echo "extra-substituters = https://bark.cachix.org" | sudo tee -a /etc/nix/nix.conf && \
	echo "extra-trusted-public-keys = bark.cachix.org-1:Iaihe4ABbOQz1CHBoYUZS/sHVAcISasJZ+lL3I4gRB0=" | sudo tee -a /etc/nix/nix.conf

RUN echo "clone bark" && \
	git clone -b master https://gitlab.com/ark-bitcoin/bark.git

RUN echo "build nix devShells and pin as GC roots" && \
	. /etc/profile.d/nix.sh && \
	cd ~/bark && \
	nix flake archive && \
	mkdir -p /home/nixuser/.nix-gc-roots && \
	nix build .#devShells.x86_64-linux.default --out-link /home/nixuser/.nix-gc-roots/dev-default && \
	nix build .#devShells.x86_64-linux.ci --out-link /home/nixuser/.nix-gc-roots/dev-ci && \
	nix build .#devShells.x86_64-linux.msrv-lib --out-link /home/nixuser/.nix-gc-roots/dev-msrv-lib

# Pre-build the nix release packages and pin them as GC roots. Release jobs
# rebuild only what changed since (the dependency derivations stay valid as
# long as the Cargo.tomls/lock don't change), so this keeps tag pipelines fast.
RUN echo "pre-build nix release packages and pin as GC roots" && \
	. /etc/profile.d/nix.sh && \
	cd ~/bark && \
	for pkg in \
		bark-x86_64-unknown-linux-gnu \
		bark-x86_64-unknown-linux-musl \
		bark-aarch64-unknown-linux-musl \
		bark-armv7-unknown-linux-musleabihf \
		bark-x86_64-apple-darwin \
		bark-aarch64-apple-darwin \
		bark-x86_64-pc-windows-gnu \
		bark-server-x86_64-unknown-linux-gnu \
		bark-server-x86_64-unknown-linux-musl; \
	do \
		nix build ".#$pkg" --out-link "/home/nixuser/.nix-gc-roots/$pkg"; \
	done

RUN echo "build bark" && \
	. /etc/profile.d/nix.sh && \
	cd ~/bark && \
	nix develop .#msrv-lib --command bash -c "just build-msrv-lib" && \
	nix develop .#ci       --command bash -c "just ci-warmup"
