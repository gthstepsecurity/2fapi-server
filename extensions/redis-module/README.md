# redis-2fapi — Zero-Knowledge Proof Authentication for Redis

A Redis module that adds Zero-Knowledge Proof (ZKP) authentication commands to Redis. Clients prove knowledge of a secret without revealing it, using Pedersen commitments over Ristretto255.

## Features

- **Zero-knowledge**: the server stores only commitments, never secrets
- **Per-client isolation**: key-level ACLs restrict access based on authenticated identity
- **Replay-resistant**: nonce-based challenges with configurable TTL
- **Fast**: <2ms verification using constant-time elliptic curve operations
- **Compatible**: works alongside Redis AUTH, Redis ACLs, and Redis Stack modules

## Installation

### Docker (recommended)

```bash
docker build -t redis-2fapi:latest extensions/redis-module/
docker run -d --name redis-2fapi \
  -p 6379:6379 \
  redis-2fapi:latest
```

### MODULE LOAD (runtime)

```bash
# Copy the shared library to the Redis modules directory
cp target/release/libredis_2fapi.so /usr/lib/redis/modules/

# Load at runtime
redis-cli MODULE LOAD /usr/lib/redis/modules/libredis_2fapi.so
```

### Persistent (redis.conf)

Add to your `redis.conf`:

```
loadmodule /usr/lib/redis/modules/libredis_2fapi.so
```

Then restart Redis:

```bash
sudo systemctl restart redis
```

### From Source

Prerequisites: Rust 1.82+, Redis 7.0+.

```bash
cd extensions/redis-module
cargo build --release --features redis-module

# Strip for production (reduces binary from ~8MB to <5MB)
strip target/release/libredis_2fapi.so

# Load into Redis
redis-cli MODULE LOAD $(pwd)/target/release/libredis_2fapi.so
```

## Quick Start

### 1. Verify the Module is Loaded

```
> MODULE LIST
1) 1) "name"
   2) "2fapi"
   3) "ver"
   4) 1
```

### 2. Enroll a Client

```
> 2FAPI.ENROLL alice-payments abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
OK
```

### 3. Request a Challenge

```
> 2FAPI.CHALLENGE alice-payments
1) "a1b2c3d4-e5f6-7890-abcd-ef1234567890"   # challenge_id
2) "deadbeef1234567890abcdef..."               # nonce (hex)
```

### 4. Verify a Proof

```
> 2FAPI.VERIFY alice-payments a1b2c3d4-e5f6-7890-abcd-ef1234567890 <proof_hex>
OK
```

### 5. Check Client Status

```
> 2FAPI.STATUS alice-payments
active
```

## Command Reference

### `2FAPI.ENROLL <client_id> <commitment_hex>`

Enrolls a new client with their Pedersen commitment.

- **client_id**: unique string identifier
- **commitment_hex**: hex-encoded 32-byte Ristretto255 point (C = g^s * h^r)
- **Returns**: `OK` on success
- **Errors**: `ERR client already enrolled` if the client_id is taken

**Complexity**: O(1)

### `2FAPI.CHALLENGE <client_id>`

Issues a fresh challenge nonce for the specified client.

- **client_id**: must be an enrolled, active client
- **Returns**: array of `[challenge_id, nonce_hex]`
- **Errors**: `ERR unknown client` if not enrolled

**Complexity**: O(1)
**Side effect**: creates a time-limited challenge entry (default: 120s TTL)

### `2FAPI.VERIFY <client_id> <challenge_id> <proof_hex>`

Verifies a ZKP proof against the stored commitment and challenge nonce.

- **client_id**: the client claiming authentication
- **challenge_id**: the UUID from a prior `2FAPI.CHALLENGE` call
- **proof_hex**: hex-encoded Sigma proof (~128 bytes)
- **Returns**: `OK` if the proof is valid, `DENIED` if not
- **Errors**: `ERR challenge not found` if the challenge expired or was already consumed

**Complexity**: O(1)
**Side effect**: consumes the challenge (single-use, prevents replay)

### `2FAPI.STATUS <client_id>`

Returns the enrollment status of a client.

- **Returns**: `active`, `suspended`, `revoked`, or `unknown`

**Complexity**: O(1)

### `2FAPI.REVOKE <client_id>`

Revokes a client's enrollment. Their commitment is marked inactive and all pending challenges are deleted.

- **Returns**: `OK` on success

**Complexity**: O(N) where N is the number of pending challenges for the client

### `2FAPI.INFO`

Returns module information and statistics.

- **Returns**: array of key-value pairs:
  - `version`: module version
  - `enrolled_clients`: number of enrolled clients
  - `active_challenges`: number of pending challenges
  - `total_verifications`: lifetime verification count

**Complexity**: O(1)

## ACL Configuration

redis-2fapi integrates with Redis ACLs. You can restrict which users can execute 2FApi commands:

```
# Allow the 'admin' user to enroll and revoke clients
ACL SETUSER admin on >password ~* +2FAPI.ENROLL +2FAPI.REVOKE +2FAPI.STATUS

# Allow the 'app' user to issue challenges and verify proofs
ACL SETUSER app on >password ~app:* +2FAPI.CHALLENGE +2FAPI.VERIFY +2FAPI.STATUS

# Deny the 'readonly' user from any 2FApi commands
ACL SETUSER readonly on >password ~* -2FAPI.*
```

### Recommended Production ACL Setup

```
# Admin: full 2FApi access
ACL SETUSER 2fapi-admin on >strongpassword ~twofapi:* +2FAPI.*

# Application: challenge + verify only (cannot enroll or revoke)
ACL SETUSER 2fapi-app on >apppassword ~app:* +2FAPI.CHALLENGE +2FAPI.VERIFY +2FAPI.STATUS +GET +SET +DEL

# Monitoring: read-only status checks
ACL SETUSER 2fapi-monitor on >monpassword ~* +2FAPI.STATUS +2FAPI.INFO
```

## Data Storage

redis-2fapi stores its data in Redis keys under a dedicated prefix:

| Key Pattern | Content |
|-------------|---------|
| `twofapi:client:<client_id>` | Client enrollment data (commitment, status) |
| `twofapi:challenge:<challenge_id>` | Challenge data (nonce, client_id, TTL) |
| `twofapi:stats` | Global verification statistics |

These keys are managed entirely by the module. Do not modify them directly.

## Compatibility

### Redis Versions

| Version | Status |
|---------|--------|
| Redis 7.0 | Supported |
| Redis 7.2 | Supported |
| Redis 7.4 | Supported (primary target) |

### Redis Stack

redis-2fapi is compatible with Redis Stack. It can be loaded alongside:

- RedisJSON
- RediSearch
- RedisTimeSeries
- RedisBloom
- RedisGraph

No command name collisions exist (all commands are prefixed with `2FAPI.`).

## Security Considerations

### Cryptographic Guarantees

- **Commitment scheme**: Pedersen commitments over Ristretto255 (128-bit security under DLOG)
- **Proof system**: Schnorr/Sigma protocol with Fiat-Shamir transform
- **Constant-time**: all cryptographic operations use the `subtle` crate
- **Memory safety**: secrets are zeroized after use via the `zeroize` crate

### Deployment Recommendations

1. **Enable TLS**: always use Redis TLS in production (`tls-port`, `tls-cert-file`, etc.)
2. **Use ACLs**: restrict which users can execute enrollment and revocation commands
3. **Monitor challenges**: use `2FAPI.INFO` to track active challenge count
4. **Persistence**: enable RDB or AOF to persist enrollment data across restarts
5. **Backups**: client commitments are critical data — include `twofapi:client:*` keys in backups

### What redis-2fapi Does NOT Do

- It does not replace Redis AUTH or ACLs (use alongside for defense-in-depth)
- It does not encrypt data at rest (use Redis encryption or disk encryption)
- It does not provide key management (clients manage their own secrets)
- It does not handle TLS termination (configure Redis TLS separately)

## License

Apache-2.0
