FROM docker.io/secondark/bark

RUN apk update
RUN apk upgrade
RUN apk add busybox-extras
RUN apk add dos2unix

RUN mkdir -p /root/bark/
ADD ./contrib/docker/bark_run.sh /root/bark/run.sh
RUN chmod a+x /root/bark/run.sh
RUN dos2unix /root/bark/run.sh

ENTRYPOINT ["/root/bark/run.sh"]


