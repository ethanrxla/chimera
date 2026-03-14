FROM rust:1.94-bookworm

RUN apt-get update && apt-get install -y \
    bash ca-certificates pkg-config libssl-dev git \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ENV CARGO_HOME=/cargo
ENV RUSTUP_HOME=/rustup
ENV PATH=/cargo/bin:${PATH}

CMD ["bash", "-lc", "cd /app/chimera/chimera-cli && cargo run -- --help"]
