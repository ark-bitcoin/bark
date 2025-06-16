FROM --platform=linux/arm/v7 debian:bookworm-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        telnet \
        dos2unix \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY ./bark-linux-armv7 /usr/local/bin/bark
COPY ./.woodpecker/images/releases/bark/run.sh /run.sh

RUN chmod a+x /usr/local/bin/bark && \
    chmod a+x /run.sh && \
    dos2unix /run.sh

CMD ["/run.sh"]