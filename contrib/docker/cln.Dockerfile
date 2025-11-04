FROM docker.io/elementsproject/lightningd:v25.09.1

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	git \
	curl \
	gcc \
	libpq-dev \
	libsqlite3-dev \
	protobuf-compiler \
	ca-certificates \
	dos2unix

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN_VERSION=1.90 \
	CLN_VERSION=25.09.1 \
	PATH=/root/.cargo/bin:${PATH}

RUN apt-get update && apt-get install -y curl git protobuf-compiler build-essential clang libsqlite3-dev libpq-dev

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION}

RUN echo "Installing c-lightning hold invoice plugin in /hold/" && \
	git clone https://github.com/BoltzExchange/hold.git && \
	cd hold && \
	git checkout 1e5dec4b479397d77c813060dd01263d689469bc && \
	cargo build && \
	chown root:root /hold/target/debug/hold && \
	chmod a+x /hold/target/debug/hold

RUN echo "Copy plugins to /plugins" && \
	mkdir /plugins && \
	cp /hold/target/debug/hold /plugins && \
	chown root:root /plugins/hold

RUN mkdir -p /root/cln/
ADD ./contrib/docker/cln_start.sh /root/cln/start.sh

RUN chmod a+x /root/cln/start.sh && \
	dos2unix /root/cln/start.sh

EXPOSE 9735
EXPOSE 9736
EXPOSE 9988