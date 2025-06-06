FROM docker.io/secondark/bark

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        telnet \
        dos2unix \
        && apt-get clean && rm -rf /var/lib/apt/lists/*

ADD ./contrib/docker/bark_run.sh /bark_run.sh

RUN chmod a+x /bark_run.sh && \
    dos2unix /bark_run.sh

ENTRYPOINT ["/bark_run.sh"]


