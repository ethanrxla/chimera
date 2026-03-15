FROM rust:1.94-bookworm

RUN apt-get update && apt-get install -y \
    bash ca-certificates pkg-config libssl-dev git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["bash", "-lc", "exec sleep infinity"]
