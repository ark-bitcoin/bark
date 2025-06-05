FROM docker.io/secondark/bark

RUN apk update
RUN apk upgrade
RUN apk add busybox-extras
RUN apk add dos2unix

ADD ./contrib/docker/bark_run.sh /bark_run.sh
RUN chmod a+x /bark_run.sh
RUN dos2unix /bark_run.sh

ENTRYPOINT ["/bark_run.sh"]


