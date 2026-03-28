# redis-2fapi — Redis 7.4 with Zero-Knowledge Proof authentication module
#
# Build (from project root):
#   docker build -f extensions/redis-module/Dockerfile -t redis-2fapi:latest .
#
# Run:
#   docker run -d --name redis-2fapi -p 6380:6379 redis-2fapi:latest
#
# Test:
#   redis-cli -p 6380 2FAPI.INFO

# ============================================
# Stage 1: Build the Redis module in Rust
# ============================================
FROM rust:1.93-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libclang-dev clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY crypto-core/ crypto-core/
COPY extensions/redis-module/ extensions/redis-module/

WORKDIR /build/extensions/redis-module
RUN cargo build --release --features redis-module

# Strip binary to reduce size
RUN strip target/release/libredis_2fapi.so

# Verify the module exports the expected symbol
RUN nm -D target/release/libredis_2fapi.so | grep RedisModule_OnLoad

# ============================================
# Stage 2: Production image
# ============================================
FROM redis:7.4-bookworm

COPY --from=builder /build/extensions/redis-module/target/release/libredis_2fapi.so \
    /usr/lib/redis/modules/libredis_2fapi.so

# Security hardening: rename dangerous commands in production.
# FIX RD-082/084/090: SLAVEOF, DEBUG, FLUSHALL, FLUSHDB, CONFIG, KEYS, MIGRATE
# These are renamed to empty string (disabled) or random prefix.
COPY extensions/redis-module/redis-hardened.conf /usr/local/etc/redis/redis-hardened.conf

CMD ["redis-server", \
     "/usr/local/etc/redis/redis-hardened.conf", \
     "--loadmodule", "/usr/lib/redis/modules/libredis_2fapi.so"]

EXPOSE 6379
