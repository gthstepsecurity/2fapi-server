# pg_2fapi — Zero-Knowledge Proof Authentication for PostgreSQL

A PostgreSQL extension that brings Zero-Knowledge Proof (ZKP) authentication directly into the database engine. Combined with Row-Level Security, it enforces per-client data isolation at the SQL level — impossible to bypass from application code.

## Features

- **Zero-knowledge**: the server stores only Pedersen commitments, never secrets
- **Database-native**: authentication runs inside PostgreSQL, not in application middleware
- **Row-Level Security**: automatic per-client data filtering via `twofapi.current_client()`
- **Replay-resistant**: nonce-based challenges with configurable TTL
- **Fast**: <5ms verification using Ristretto255 elliptic curve operations
- **Constant-time**: all cryptographic operations are timing-safe

## Installation

### Docker (recommended)

```bash
docker build -t pg-2fapi:latest extensions/pg-extension/
docker run -d --name pg-2fapi \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 \
  pg-2fapi:latest
```

The Docker image automatically creates the extension on first startup.

### From Debian Package

```bash
# Download the package for your PostgreSQL version
sudo dpkg -i pg-2fapi_0.1.0_pg17_amd64.deb
sudo systemctl restart postgresql

# Connect and create the extension
psql -U postgres -c "CREATE EXTENSION pg_2fapi;"
```

### From Source

Prerequisites: Rust 1.82+, `cargo-pgrx`, PostgreSQL development headers.

```bash
# Install cargo-pgrx (one-time)
cargo install cargo-pgrx --version 0.12.9 --locked
cargo pgrx init --pg17 $(which pg_config)

# Build and install
cd extensions/pg-extension
cargo pgrx install --release --features pg17

# Create the extension
psql -U postgres -c "CREATE EXTENSION pg_2fapi;"
```

## Quick Start

### 1. Create the Extension

```sql
CREATE EXTENSION pg_2fapi;
SELECT twofapi.pg_2fapi_version();
-- Returns: 0.1.0
```

### 2. Enroll a Client

```sql
-- The client generates a Pedersen commitment C = g^s * h^r offline
-- and sends only C (32 bytes) to the server
SELECT twofapi.enroll(
  'alice-payments',                        -- client_id
  '\xabcdef1234567890abcdef1234567890'     -- commitment (bytea, 32 bytes)
  '\xfedcba0987654321fedcba0987654321'     -- proof_of_possession (bytea)
);
```

### 3. Request a Challenge

```sql
SELECT * FROM twofapi.challenge('alice-payments');
-- Returns: challenge_id (uuid), nonce (text, hex)
```

### 4. Verify a Proof

```sql
SELECT twofapi.authenticate(
  'alice-payments',                        -- client_id
  'a1b2c3d4-...',                          -- challenge_id (from step 3)
  '\x...'                                  -- proof (bytea, Sigma proof)
);
-- Returns: true (verified) or false (rejected)
```

### 5. Enable Row-Level Security

```sql
-- Create your application table
CREATE TABLE invoices (
  id SERIAL PRIMARY KEY,
  client_id TEXT NOT NULL,
  amount DECIMAL(12,2),
  description TEXT
);

-- Enable RLS
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;

-- Create policies referencing the authenticated client
CREATE POLICY zkp_read ON invoices
  FOR SELECT
  USING (client_id = current_setting('twofapi.current_client_id', true));

CREATE POLICY zkp_write ON invoices
  FOR INSERT
  WITH CHECK (client_id = current_setting('twofapi.current_client_id', true));
```

Now, after `twofapi.authenticate()` succeeds, all queries on the `invoices` table automatically filter by the authenticated client.

## Configuration

pg_2fapi exposes the following GUC (Grand Unified Configuration) variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `twofapi.challenge_ttl_seconds` | `120` | How long a challenge nonce remains valid |
| `twofapi.max_challenges_per_client` | `5` | Maximum concurrent challenges per client |
| `twofapi.log_level` | `notice` | Logging verbosity: `debug`, `notice`, `warning`, `error` |
| `twofapi.current_client_id` | `""` | Session variable set by `authenticate()` — used by RLS policies |

Set them in `postgresql.conf` or per-session:

```sql
-- Per-session
SET twofapi.challenge_ttl_seconds = 60;

-- Permanent (postgresql.conf)
-- twofapi.challenge_ttl_seconds = 300
```

## SQL Function Reference

### `twofapi.pg_2fapi_version() -> text`

Returns the extension version string.

### `twofapi.enroll(client_id text, commitment bytea) -> boolean`

Enrolls a new client with their Pedersen commitment.

- **client_id**: unique identifier for the client
- **commitment**: 32-byte Ristretto255 compressed point (C = g^s * h^r)
- **Returns**: `true` on success, `false` if client already exists

### `twofapi.challenge(client_id text) -> TABLE(challenge_id uuid, nonce text)`

Issues a fresh challenge for the specified client.

- **client_id**: must be an enrolled, active client
- **Returns**: a UUID challenge identifier and a hex-encoded nonce
- **Side effect**: invalidates any previous challenges for this client (beyond the max limit)

### `twofapi.authenticate(client_id text, challenge_id text, proof bytea) -> boolean`

Verifies a ZKP proof and establishes an authenticated session.

- **client_id**: the client claiming authentication
- **challenge_id**: the UUID from a prior `challenge()` call
- **proof**: the Sigma proof (serialized, ~128 bytes)
- **Returns**: `true` if the proof is valid
- **Side effect**: sets `twofapi.current_client_id` for the current transaction (via `SET LOCAL`)
- **Note**: consumes the challenge (single-use)

### `twofapi.current_client() -> text`

Returns the currently authenticated client ID, or `NULL` if no session is active. Alias for `current_setting('twofapi.current_client_id', true)`.

### `twofapi.revoke(client_id text) -> boolean`

Revokes a client's enrollment. Their commitment is marked as inactive, and all pending challenges are deleted.

### `twofapi.status(client_id text) -> text`

Returns the client's status: `active`, `suspended`, `revoked`, or `unknown`.

## Security Considerations

### Cryptographic Guarantees

- **Commitment scheme**: Pedersen commitments over Ristretto255 (128-bit security under DLOG)
- **Proof system**: Schnorr/Sigma protocol with Fiat-Shamir transform
- **Non-interactive**: challenge binding via `c = H(g || h || C || A || nonce)`
- **Constant-time**: all operations on secret data use the `subtle` crate for timing safety
- **Memory**: secrets are zeroized after use via the `zeroize` crate

### Deployment Recommendations

1. **Use `shared_preload_libraries`**: ensures the extension is loaded at server start
2. **Restrict `SUPERUSER`**: only superusers can create the extension; regular users call the functions
3. **Monitor challenges**: old challenges consume memory; they are auto-cleaned on TTL expiry
4. **Backup commitments**: client commitments are stored in the `twofapi.clients` table — include in backups
5. **TLS**: always use TLS for client-to-PostgreSQL connections (proof bytes are not secret, but integrity matters)

### What pg_2fapi Does NOT Do

- It does not manage TLS certificates
- It does not replace PostgreSQL's native SCRAM authentication (use both for defense-in-depth)
- It does not encrypt data at rest (use PostgreSQL's built-in encryption or disk-level encryption)
- It does not provide key management (clients manage their own secrets)

## Supported PostgreSQL Versions

| Version | Status |
|---------|--------|
| PostgreSQL 14 | Supported |
| PostgreSQL 15 | Supported |
| PostgreSQL 16 | Supported |
| PostgreSQL 17 | Supported (primary target) |

## Extension Metadata

The `pg_2fapi.control` file:

```
comment = '2FApi: Zero-Knowledge Proof authentication for PostgreSQL'
default_version = '1.0'
module_pathname = '$libdir/pg_2fapi'
relocatable = false
schema = twofapi
superuser = true
```

All objects are created in the `twofapi` schema. The extension is non-relocatable to ensure RLS policies and GUC variables reference the correct schema.

## License

Apache-2.0
