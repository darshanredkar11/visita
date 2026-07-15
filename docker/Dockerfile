# ── Stage 1: Builder ──────────────────────────────────────────────────────────
FROM rust:1.86-bookworm AS builder

# Install system deps for ring/openssl/sqlx
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifest files and all source directories
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY migrations/ migrations/

# Build the production binary
RUN cargo build --release --bin visitorpass-api

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin visitorpass

WORKDIR /app

COPY --from=builder /build/target/release/visitorpass-api /app/visitorpass-api
COPY --from=builder /build/migrations /app/migrations

# Run as non-root
USER visitorpass

# Health check for container orchestrators
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

EXPOSE 8080

ENTRYPOINT ["/app/visitorpass-api"]
