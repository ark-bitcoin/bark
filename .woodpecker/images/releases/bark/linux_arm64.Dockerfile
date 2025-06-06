FROM --platform=linux/arm64 debian:bookworm-slim
COPY bark-linux-aarch64 /usr/local/bin/bark
RUN chmod +x /usr/local/bin/bark
ENTRYPOINT ["/usr/local/bin/bark"]
