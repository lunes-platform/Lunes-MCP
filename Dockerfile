FROM rust:1.86-slim-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app --shell /usr/sbin/nologin lunes

WORKDIR /app

COPY --from=builder /app/target/release/lunes-mcp-server /usr/local/bin/lunes-mcp-server
COPY agent_config.toml ./agent_config.toml

ENV LUNES_MCP_BIND=0.0.0.0:9950
ENV RUST_LOG=info

EXPOSE 9950

USER lunes

ENTRYPOINT ["lunes-mcp-server"]
