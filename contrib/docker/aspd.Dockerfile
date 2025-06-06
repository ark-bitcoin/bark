FROM docker.io/secondark/aspd

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        postgresql \
        dos2unix \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/aspd/
ADD ./contrib/docker/aspd_start.sh /root/aspd/start.sh
ADD ./contrib/docker/aspd.toml     /root/aspd/aspd.toml

RUN chmod a+x /root/aspd/start.sh && \
    dos2unix /root/aspd/start.sh

EXPOSE 5432

CMD ["/root/aspd/start.sh"]


