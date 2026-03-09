FROM --platform=linux/arm64 debian:bookworm-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        telnet \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./bark-linux-aarch64 /usr/local/bin/bark
COPY ./barkd-linux-aarch64 /usr/local/bin/barkd
COPY ./.gitlab/images/releases/bark/run.sh /run.sh

CMD ["/run.sh"]
