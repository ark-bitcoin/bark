FROM --platform=linux/amd64 debian:bookworm-slim

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        libpq-dev \
        curl \
        gnupg2 \
        lsb-release \
        apt-transport-https \
        ca-certificates \
        dos2unix \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list
RUN curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc| gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        postgresql-16 \
        postgresql-client-16 \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/captaind/
COPY ./captaind-linux-x86_64                              /usr/local/bin/captaind
COPY ./.woodpecker/images/releases/captaind/start.sh      /root/captaind/start.sh
COPY ./.woodpecker/images/releases/captaind/captaind.toml /root/captaind/captaind.toml

RUN chmod a+x /usr/local/bin/captaind && \
    chmod a+x /root/captaind/start.sh && \
    dos2unix /root/captaind/start.sh

EXPOSE 5432
EXPOSE 3535

CMD ["/root/captaind/start.sh"]
