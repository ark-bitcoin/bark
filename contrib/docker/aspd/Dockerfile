FROM docker.io/rust:1.84.1 AS builder

RUN apt update && apt install -y build-essential clang protobuf-compiler postgresql postgresql-contrib sudo

WORKDIR /usr/src

# Make a release build for aspd
# We bind-mounts ensure we can add all the code to our repository
# The cache mounts ensures the cargo build-cache works as expected
RUN --mount=type=bind,source=Cargo.toml,target=/usr/src/Cargo.toml \
  --mount=type=bind,source=Cargo.lock,target=/usr/src/Cargo.lock \
  --mount=type=bind,source=ark-lib,target=/usr/src/ark-lib \
  --mount=type=bind,source=aspd,target=/usr/src/aspd \
  --mount=type=bind,source=aspd-log,target=/usr/src/aspd-log \
  --mount=type=bind,source=aspd-rpc,target=/usr/src/aspd-rpc \
  --mount=type=bind,source=ark-testing,target=/usr/src/ark-testing \
  --mount=type=bind,source=bark,target=/usr/src/bark \
  --mount=type=bind,source=bark-json,target=/usr/src/bark-json \
  --mount=type=bind,source=bark-cln,target=/usr/src/bark-cln \
  --mount=type=bind,source=stream-until,target=/usr/src/stream-until \
  --mount=type=cache,target=/usr/src/target \
  --mount=type=cache,target=/usr/local/cargo/git \
  --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build --package bark-aspd --release --locked

ENV POSTGRES_USER=postgres
ENV POSTGRES_PASSWORD=postgres

RUN service postgresql start && \
	sudo -u postgres psql -c "ALTER USER $POSTGRES_USER WITH PASSWORD '$POSTGRES_PASSWORD';"

RUN --mount=type=cache,target=/usr/src/target \
  cp /usr/src/target/release/aspd /usr/local/bin/aspd

FROM docker.io/debian:12 AS runner

# Create the datadir
RUN mkdir /data
ENV ASPD_DATADIR=/data/aspd

ADD /contrib/docker/aspd/entrypoint.sh /entrypoint.sh

COPY --from=builder /usr/local/bin/aspd /usr/local/bin/aspd

ENTRYPOINT ["/entrypoint.sh"]
CMD ["aspd"]


