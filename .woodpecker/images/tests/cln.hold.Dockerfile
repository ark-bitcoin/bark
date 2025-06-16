FROM elementsproject/lightningd:v25.02.2

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN_VERSION=1.82 \
	PATH=/root/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y curl git protobuf-compiler build-essential clang libsqlite3-dev libpq-dev

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

RUN echo "Moving plugins to /plugins" && \
	mkdir /plugins && \
	cp /hold/target/debug/hold /plugins && \
	chown root:root /plugins/hold