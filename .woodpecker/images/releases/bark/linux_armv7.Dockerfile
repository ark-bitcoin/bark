FROM --platform=linux/arm/v7 debian:bookworm-slim
COPY bark-linux-armv7 /usr/local/bin/bark
RUN chmod +x /usr/local/bin/bark
ENTRYPOINT ["/usr/local/bin/bark"]