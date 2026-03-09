FROM --platform=linux/arm/v7 debian:bookworm-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        telnet \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./bark-linux-armv7 /usr/local/bin/bark
COPY ./barkd-linux-armv7 /usr/local/bin/barkd
COPY ./.gitlab/images/releases/bark/run.sh /run.sh

CMD ["/run.sh"]