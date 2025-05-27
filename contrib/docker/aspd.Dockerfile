FROM docker.io/secondark/aspd

RUN apk update
RUN apk upgrade
RUN apk add postgresql
RUN apk add dos2unix

RUN mkdir -p /root/aspd/
ADD ./contrib/docker/aspd_start.sh /root/aspd/start.sh
ADD ./contrib/docker/aspd.toml     /root/aspd/aspd.toml
RUN chmod a+x /root/aspd/start.sh
RUN dos2unix /root/aspd/start.sh

EXPOSE 5432

CMD ["/root/aspd/start.sh"]


