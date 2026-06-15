FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY target/release/metis /usr/local/bin/metis

ENTRYPOINT ["/usr/local/bin/metis"]
CMD ["--config", "/etc/metis/metis.toml"]
