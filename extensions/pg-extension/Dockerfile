# =============================================================================
# pg_2fapi — PostgreSQL Extension Docker Image
# =============================================================================
# Multi-stage build: compile the extension with pgrx, then copy artifacts
# into a stock PostgreSQL 17 image.
#
# Build:
#   docker build -t pg-2fapi:latest .
#
# Run:
#   docker run -d --name pg-2fapi \
#     -e POSTGRES_PASSWORD=secret \
#     -p 5432:5432 \
#     pg-2fapi:latest
#
# Then:
#   psql -h localhost -U postgres -c "CREATE EXTENSION pg_2fapi;"
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build the extension with cargo-pgrx
# ---------------------------------------------------------------------------
FROM rust:1.82-bookworm AS builder

# Install PostgreSQL 17 development headers (needed by pgrx)
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-server-dev-17 \
    libclang-dev \
    clang \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-pgrx (must match the pgrx version in Cargo.toml)
RUN cargo install cargo-pgrx --version 0.12.9 --locked
RUN cargo pgrx init --pg17 /usr/lib/postgresql/17/bin/pg_config

# Copy the workspace needed for building
WORKDIR /build
COPY ../../crypto-core ./crypto-core
COPY . ./extensions/pg-extension

WORKDIR /build/extensions/pg-extension

# Build the extension in release mode for PostgreSQL 17
RUN cargo pgrx package --pg-config /usr/lib/postgresql/17/bin/pg_config --features pg17

# The artifacts land in target/release/pg_2fapi-pg17/
# Locate the built files
RUN find target/ -name "pg_2fapi.so" -o -name "pg_2fapi.control" -o -name "pg_2fapi--1.0.sql" \
    | head -20

# ---------------------------------------------------------------------------
# Stage 2: Production image based on stock PostgreSQL 17
# ---------------------------------------------------------------------------
FROM postgres:17-bookworm

LABEL maintainer="2FApi Team"
LABEL description="PostgreSQL 17 with pg_2fapi Zero-Knowledge Proof authentication extension"
LABEL version="0.1.0"

# Copy the compiled extension artifacts from the builder stage
COPY --from=builder /build/extensions/pg-extension/target/release/pg_2fapi-pg17/usr/lib/postgresql/17/lib/pg_2fapi.so \
    /usr/lib/postgresql/17/lib/pg_2fapi.so

COPY --from=builder /build/extensions/pg-extension/target/release/pg_2fapi-pg17/usr/share/postgresql/17/extension/pg_2fapi.control \
    /usr/share/postgresql/17/extension/pg_2fapi.control

COPY --from=builder /build/extensions/pg-extension/target/release/pg_2fapi-pg17/usr/share/postgresql/17/extension/pg_2fapi--1.0.sql \
    /usr/share/postgresql/17/extension/pg_2fapi--1.0.sql

# Pre-load the extension shared library so that session variables are available
RUN echo "shared_preload_libraries = 'pg_2fapi'" >> /usr/share/postgresql/postgresql.conf.sample

# Add an init script that creates the extension on the default database
COPY <<'INIT_SQL' /docker-entrypoint-initdb.d/01-create-2fapi-extension.sql
-- Automatically create the pg_2fapi extension on first startup
CREATE EXTENSION IF NOT EXISTS pg_2fapi;

-- Verify installation
DO $$
BEGIN
  RAISE NOTICE '2FApi extension installed. Version: %', twofapi.pg_2fapi_version();
END $$;
INIT_SQL

EXPOSE 5432
