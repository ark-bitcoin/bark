FROM --platform=linux/amd64 debian:bookworm-slim
COPY bark-linux-x86_64 /usr/local/bin/bark
RUN chmod +x /usr/local/bin/bark
ENTRYPOINT ["/usr/local/bin/bark"]