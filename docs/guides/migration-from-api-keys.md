# Migration Guide: From API Keys to 2FApi Extensions

This guide walks you through migrating from traditional API key authentication to Zero-Knowledge Proof authentication using 2FApi extensions (PostgreSQL or Redis).

## Why Migrate?

| Aspect | API Keys | 2FApi (ZKP) |
|--------|----------|-------------|
| Shared secrets | Server stores plaintext/hashed keys | Server stores only commitments |
| Key rotation | Disruptive — all clients must update | Not needed — proofs are ephemeral |
| Breach impact | Attacker can impersonate any client | Commitments are useless without secrets |
| Data isolation | Application-level filtering | Database-level enforcement (RLS/ACL) |
| Replay attacks | Possible if key is leaked | Impossible — nonce-based, single-use |

## Migration Strategy

The migration follows a phased approach. Each phase is independently deployable and rollbackable.

```
Phase 1          Phase 2          Phase 3          Phase 4
Install ext.     Dual-auth        Switch reads     Remove old
   |                |                |                |
   v                v                v                v
[API keys]   [API keys + ZKP]   [ZKP primary]   [ZKP only]
```

---

## Path A: PostgreSQL (pg_2fapi)

### Step 1: Install the pg_2fapi Extension

```bash
# Option 1: Docker (recommended for first-time setup)
docker run -d --name pg-2fapi \
  -e POSTGRES_PASSWORD=secret \
  -p 5432:5432 \
  pg-2fapi:latest

# Option 2: From .deb package
sudo dpkg -i pg-2fapi_0.1.0_pg17_amd64.deb
sudo systemctl restart postgresql

# Option 3: From source
cd extensions/pg-extension
cargo pgrx install --release --features pg17
```

Then create the extension in your database:

```sql
CREATE EXTENSION pg_2fapi;

-- Verify installation
SELECT twofapi.pg_2fapi_version();
-- Returns: 0.1.0
```

**Rollback**: `DROP EXTENSION pg_2fapi CASCADE;` removes all 2FApi objects without affecting application tables.

### Step 2: Enroll Existing Clients

For each client that currently has an API key, generate a Pedersen commitment. The client performs this operation locally (the secret never leaves the client).

```sql
-- Server-side: register the commitment
SELECT twofapi.enroll('alice-payments', '\xabcdef...'::bytea);
SELECT twofapi.enroll('bob-payments', '\x123456...'::bytea);
```

The client-side enrollment flow:

```
1. Client generates secret s and blinding factor r
2. Client computes commitment C = g^s * h^r  (Ristretto255)
3. Client sends C (32 bytes) to the server
4. Server calls twofapi.enroll(client_id, C)
5. Client stores (s, r) securely (e.g., encrypted keystore)
```

**Important**: The server never sees `s` or `r`. Only the commitment `C` is stored.

### Step 3: Update Middleware to Support Both Auth Methods

Modify your application middleware to accept **both** API keys and ZKP proofs during the transition period.

```python
# Django example — dual authentication middleware
class DualAuthMiddleware:
    def __call__(self, request):
        # Try ZKP first
        client_id = request.META.get("HTTP_X_CLIENT_ID")
        proof = request.META.get("HTTP_X_ZKP_PROOF")
        challenge_id = request.META.get("HTTP_X_CHALLENGE_ID")

        if client_id and proof and challenge_id:
            # New path: ZKP authentication
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT twofapi.authenticate(%s, %s, %s)",
                    [client_id, challenge_id, bytes.fromhex(proof)]
                )
                verified = cursor.fetchone()[0]

            if verified:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SET LOCAL twofapi.current_client_id = %s",
                        [client_id]
                    )
                request.auth_method = "zkp"
                return self.get_response(request)

        # Fallback: API key authentication (legacy)
        api_key = request.META.get("HTTP_X_API_KEY")
        if api_key:
            client = ApiKey.objects.filter(key=api_key, active=True).first()
            if client:
                request.auth_method = "api_key"
                # Log for migration tracking
                logger.info(
                    "Legacy API key auth used by %s — nudge to ZKP",
                    client.client_id
                )
                return self.get_response(request)

        return JsonResponse({"error": "unauthorized"}, status=401)
```

### Step 4: Enable Row-Level Security

```sql
-- Enable RLS on application tables
ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
ALTER TABLE invoices FORCE ROW LEVEL SECURITY;

-- Create policy referencing the ZKP session variable
CREATE POLICY zkp_access ON invoices
  USING (client_id = current_setting('twofapi.current_client_id', true));

CREATE POLICY zkp_insert ON invoices
  WITH CHECK (client_id = current_setting('twofapi.current_client_id', true));
```

**Note**: During the dual-auth phase, ensure legacy API key clients also have `twofapi.current_client_id` set (map API key to client_id in your middleware).

### Step 5: Monitor and Verify Transition

Track which clients are still using API keys:

```sql
-- Create a migration tracking table
CREATE TABLE auth_migration_log (
  client_id TEXT NOT NULL,
  auth_method TEXT NOT NULL,  -- 'api_key' or 'zkp'
  last_seen TIMESTAMPTZ DEFAULT now(),
  PRIMARY KEY (client_id, auth_method)
);

-- Query: who is still using API keys?
SELECT client_id, last_seen
FROM auth_migration_log
WHERE auth_method = 'api_key'
ORDER BY last_seen DESC;
```

Set a target date and notify clients still using API keys.

### Step 6: Deprecate API Keys

Once all clients have migrated:

```sql
-- 1. Remove the fallback from middleware (code change)
-- 2. Revoke API keys
UPDATE api_keys SET active = false;

-- 3. After a grace period, drop the table
DROP TABLE api_keys;
```

---

## Path B: Redis (redis-2fapi)

### Step 1: Load the redis-2fapi Module

```bash
# Option 1: Docker
docker run -d --name redis-2fapi \
  -p 6379:6379 \
  redis-2fapi:latest

# Option 2: Runtime load
redis-cli MODULE LOAD /path/to/libredis_2fapi.so

# Option 3: Persistent (redis.conf)
# Add to redis.conf:
# loadmodule /usr/lib/redis/modules/libredis_2fapi.so
```

Verify:

```
redis-cli MODULE LIST
# Should include: name=2fapi ver=1 ...
```

**Rollback**: `MODULE UNLOAD 2fapi` removes the module. Existing Redis data is unaffected.

### Step 2: Enroll Existing Clients

```
# For each client with a Redis AUTH password
redis-cli 2FAPI.ENROLL alice-payments <commitment_hex>
redis-cli 2FAPI.ENROLL bob-payments <commitment_hex>
```

### Step 3: Update Client Libraries

Replace the AUTH-based connection with challenge/verify flow:

```typescript
// Before (API key / AUTH password)
const redis = new Redis({ password: "sk_live_alice_001" });

// After (ZKP authentication per operation)
const redis = new Redis(); // no password needed

async function authenticatedCall(clientId: string, proof: string) {
  const challengeId = req.headers["x-challenge-id"];
  const result = await redis.call("2FAPI.VERIFY", clientId, challengeId, proof);
  if (result !== "OK") throw new Error("Authentication failed");
  // Proceed with data operations...
}
```

### Step 4: Run Dual-Auth Period

Keep Redis AUTH active while clients transition:

```
# Redis AUTH is still active for legacy clients
# 2FAPI commands work alongside AUTH
# Track which clients use which method in your application logs
```

### Step 5: Require 2FApi for All Connections

Once all clients have migrated:

```bash
# Remove Redis AUTH requirement
redis-cli CONFIG SET requirepass ""

# Alternatively, use Redis ACLs to restrict legacy access
redis-cli ACL SETUSER legacy off
```

### Step 6: Remove Redis AUTH

Update `redis.conf` to remove the `requirepass` directive permanently.

---

## Rollback Plan

If issues are detected at any phase, follow this rollback procedure:

### Phase 1 Rollback (Extension just installed, no clients enrolled)

```sql
-- PostgreSQL
DROP EXTENSION pg_2fapi CASCADE;
```

```
# Redis
MODULE UNLOAD 2fapi
```

### Phase 2 Rollback (Dual-auth active)

1. **Disable ZKP in middleware**: revert the code change (remove ZKP code path)
2. **Re-enable API key / AUTH as sole authentication**
3. **Verify** all clients reconnect with old authentication
4. **Remove extension** once confirmed

```sql
-- PostgreSQL: remove RLS policies, then extension
DROP POLICY IF EXISTS zkp_access ON invoices;
DROP POLICY IF EXISTS zkp_insert ON invoices;
ALTER TABLE invoices DISABLE ROW LEVEL SECURITY;
DROP EXTENSION pg_2fapi CASCADE;
```

```
# Redis: unload module
MODULE UNLOAD 2fapi
```

### Phase 3/4 Rollback (ZKP is primary or sole auth)

This is more involved — you need to re-generate API keys for clients:

1. **Generate new API keys** for each enrolled client
2. **Re-enable API key middleware**
3. **Distribute new keys** to clients
4. **Revert** to API key auth
5. **Remove 2FApi** extension

### Key Guarantees

- **No data loss**: 2FApi extensions never modify application data
- **Atomic rollback**: `DROP EXTENSION CASCADE` / `MODULE UNLOAD` cleanly remove all 2FApi objects
- **Client data preserved**: invoices, Redis keys, and all application state remain intact
- **Rollback window**: each phase should run for at least 1 week before progressing

---

## Timeline Recommendation

| Week | Action |
|------|--------|
| 1 | Install extension, enroll pilot clients |
| 2-3 | Dual-auth: both old and new auth active |
| 4 | Monitor: verify pilot clients work with ZKP |
| 5-6 | Roll out ZKP to remaining clients |
| 7 | Set ZKP as primary, API key as fallback |
| 8 | Deprecation notice for API key users |
| 10 | Disable API key authentication |
| 12 | Drop API key infrastructure |

## Troubleshooting

### "twofapi.authenticate() returns false for valid proofs"

- Verify the challenge has not expired (2-minute TTL by default)
- Ensure the challenge was issued for the correct client_id
- Check that the proof is hex-encoded (not base64)

### "RLS blocks all queries"

- Ensure `SET LOCAL twofapi.current_client_id` is called within the same transaction
- Check that RLS policies reference `current_setting('twofapi.current_client_id', true)` (the `true` makes it return NULL instead of erroring when unset)

### "2FAPI.VERIFY returns DENIED"

- Verify the client is enrolled: `2FAPI.STATUS <client_id>` should return `active`
- Ensure the challenge was not already consumed (single-use)
- Check Redis logs for module-level errors
