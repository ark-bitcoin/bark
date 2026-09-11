FROM docker.io/elementsproject/lightningd:v26.06.7

RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	clang \
	curl \
	dos2unix \
	gcc \
	git \
	libpq-dev \
	libsqlite3-dev \
	protobuf-compiler \
	python3 \
	python3-venv \
	&& rm -rf /var/lib/apt/lists/*

ENV RUST_BACKTRACE=1 \
	RUSTUP_TOOLCHAIN_VERSION=1.90 \
	CLN_VERSION=26.06.7 \
	PATH=/root/.cargo/bin:${PATH}

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain none
RUN echo "Installing Rust toolchains version ${RUSTUP_TOOLCHAIN_VERSION}..." && \
	rustup toolchain install ${RUSTUP_TOOLCHAIN_VERSION}

RUN echo "Installing c-lightning hold invoice plugin in /hold/" && \
	git clone https://gitlab.com/ark-bitcoin/hold.git && \
	cd hold && \
	cargo build && \
	chown root:root /hold/target/debug/hold && \
	chmod a+x /hold/target/debug/hold

RUN echo "Installing c-lightning prometheus plugin in /cln-plugins/" && \
	git clone https://github.com/lightningd/plugins.git cln-plugins && \
	cd cln-plugins/prometheus && \
	python3 -m venv venv && \
	venv/bin/pip install --no-cache-dir "prometheus-client>=0.26.0" "pyln-client>=25.9.3" && \
	printf '#!/bin/sh\nexec /cln-plugins/prometheus/venv/bin/python /cln-plugins/prometheus/prometheus.py "$@"\n' \
		> /cln-plugins/prometheus/cln-prometheus && \
	chown root:root /cln-plugins/prometheus/cln-prometheus && \
	chmod a+x /cln-plugins/prometheus/cln-prometheus

RUN echo "Copy plugins to /plugins" && \
	mkdir /plugins && \
	cp /hold/target/debug/hold /plugins && \
	chown root:root /plugins/hold && \
	cp /cln-plugins/prometheus/cln-prometheus /plugins && \
	chown root:root /plugins/cln-prometheus

RUN mkdir -p /root/cln/
ADD ./contrib/docker/cln_start.sh /root/cln/start.sh

RUN chmod a+x /root/cln/start.sh && \
	dos2unix /root/cln/start.sh

EXPOSE 9735
EXPOSE 9736
EXPOSE 9988
EXPOSE 9750