# Sprint 21 — Packaging, Examples & Documentation

> **Goal**: Package both extensions for distribution, provide integration examples for popular frameworks, and write migration guides.
> **Bounded Context**: Cross-cutting (distribution & developer experience)
> **Scenarios**: 18 | Happy: 14 | Edge: 2 | Error: 2
> **Prerequisites**: Sprint 18 (pg_2fapi core), Sprint 19 (redis-2fapi core), Sprint 20 (hardening)
> **Key deliverables**: .deb packages, Docker images, Django + Express examples, migration guides

---

## Feature 1: PostgreSQL Packaging (5 scenarios)

```gherkin
Feature: pg_2fapi Packaging and Distribution
  As a database administrator
  I want pg_2fapi available as native packages and Docker images
  So that I can install ZKP authentication without building from source

  Background:
    Given the pg_2fapi extension is built with cargo-pgrx
    And the Cargo.toml specifies version "0.1.0"
    And the pg_2fapi.control file declares default_version = '1.0'
    And the supported PostgreSQL major versions are 14, 15, and 16

  # --- Happy Path ---

  Scenario: cargo pgrx package produces a Debian package
    Given the build environment has cargo-pgrx installed
    And the target PostgreSQL development headers are available
    When the maintainer runs:
      """bash
      cargo pgrx package --pg-config /usr/lib/postgresql/16/bin/pg_config
      """
    Then a .deb package is produced in the target directory
    And the package contains:
      | File                                     | Location                                    |
      | pg_2fapi.so                              | /usr/lib/postgresql/16/lib/                 |
      | pg_2fapi.control                         | /usr/share/postgresql/16/extension/          |
      | pg_2fapi--1.0.sql                        | /usr/share/postgresql/16/extension/          |
    And the package depends on postgresql-16
    And the shared library links against libcurve25519-dalek (via crypto-core)

  Scenario: Debian package installs and works on Ubuntu 22.04 and 24.04
    Given a clean Ubuntu installation with PostgreSQL from the official APT repository
    And the Ubuntu version is one of:
      | Version |
      | 22.04   |
      | 24.04   |
    When the administrator installs the .deb package:
      """bash
      sudo dpkg -i pg-2fapi_0.1.0_amd64.deb
      """
    Then the package installs without errors
    And "CREATE EXTENSION pg_2fapi" succeeds on a fresh database
    And twofapi.pg_2fapi_version() returns "0.1.0"

  Scenario: Extension works with PostgreSQL 14, 15, and 16
    Given separate .deb packages built for each PostgreSQL major version
    When the extension is installed and tested on each version:
      | PostgreSQL Version | Package                             |
      | 14                 | pg-2fapi_0.1.0_pg14_amd64.deb      |
      | 15                 | pg-2fapi_0.1.0_pg15_amd64.deb      |
      | 16                 | pg-2fapi_0.1.0_pg16_amd64.deb      |
    Then CREATE EXTENSION pg_2fapi succeeds on all three versions
    And twofapi.enroll(), twofapi.challenge(), and twofapi.verify() work correctly
    And no version-specific SQL compatibility issues arise

  Scenario: Docker image with pg_2fapi pre-installed
    Given a Dockerfile based on postgres:16-bookworm
    When the image is built with:
      """dockerfile
      FROM postgres:16-bookworm
      COPY pg_2fapi.so /usr/lib/postgresql/16/lib/
      COPY pg_2fapi.control /usr/share/postgresql/16/extension/
      COPY pg_2fapi--1.0.sql /usr/share/postgresql/16/extension/
      RUN echo "shared_preload_libraries = 'pg_2fapi'" >> /usr/share/postgresql/postgresql.conf.sample
      """
    Then the Docker image builds successfully
    And "docker run ... -c 'CREATE EXTENSION pg_2fapi'" succeeds
    And the image size overhead from pg_2fapi is less than 10MB

  Scenario: Extension metadata is valid for PGXN listing
    Given the pg_2fapi.control file contains:
      | Field           | Value                                    |
      | comment         | Zero-Knowledge Proof authentication      |
      | default_version | 1.0                                      |
      | module_pathname | $libdir/pg_2fapi                         |
      | schema          | twofapi                                  |
      | relocatable     | false                                    |
    And a META.json file exists with PGXN-required fields
    When the PGXN validator checks the distribution
    Then validation passes
    And the extension can be listed on pgxn.org
```

---

## Feature 2: Redis Packaging (4 scenarios)

```gherkin
Feature: redis-2fapi Packaging and Distribution
  As a Redis administrator
  I want redis-2fapi available as a shared library and Docker image
  So that I can add ZKP authentication to any Redis deployment

  Background:
    Given the redis-2fapi module is built with cargo and redis-module-rs
    And the Cargo.toml specifies crate-type = ["cdylib"]
    And the compiled shared library is named libredis_2fapi.so

  # --- Happy Path ---

  Scenario: cargo build --release produces a loadable shared library
    Given the build environment has Rust stable toolchain and Redis development headers
    When the maintainer runs:
      """bash
      cd extensions/redis-module && cargo build --release
      """
    Then a file target/release/libredis_2fapi.so is produced
    And the shared library exports the RedisModule_OnLoad symbol
    And the binary size is less than 5MB (stripped)
    And ldd shows no unexpected external dependencies

  Scenario: Module loads on Redis 7.0, 7.2, and 7.4
    Given the compiled libredis_2fapi.so
    When MODULE LOAD is executed on each Redis version:
      | Redis Version |
      | 7.0           |
      | 7.2           |
      | 7.4           |
    Then the module loads successfully on all three versions
    And all 2FAPI commands are registered
    And 2FAPI.ENROLL and 2FAPI.VERIFY work correctly

  Scenario: Docker image with redis-2fapi pre-loaded
    Given a Dockerfile based on redis:7.2-bookworm
    When the image is built with:
      """dockerfile
      FROM redis:7.2-bookworm
      COPY libredis_2fapi.so /usr/lib/redis/modules/
      CMD ["redis-server", "--loadmodule", "/usr/lib/redis/modules/libredis_2fapi.so"]
      """
    Then the Docker image builds successfully
    And "docker run ... redis-cli 2FAPI.STATUS test" returns "unknown"
    And the image size overhead from redis-2fapi is less than 5MB

  # --- Edge Case ---

  Scenario: Module is compatible with Redis Stack
    Given a Redis Stack deployment (redis-stack:latest)
    When the administrator loads the 2fapi module alongside existing Stack modules:
      """
      MODULE LOAD /usr/lib/redis/modules/libredis_2fapi.so
      """
    Then the module loads without conflicts
    And existing Stack modules (RedisJSON, RediSearch, etc.) continue to function
    And 2FAPI commands do not collide with any Stack module commands
```

---

## Feature 3: Example — Django + pg_2fapi (3 scenarios)

```gherkin
Feature: Django Integration Example with pg_2fapi
  As a Django developer
  I want a working example of Django with pg_2fapi and Row-Level Security
  So that I can adopt ZKP authentication in my existing Django application

  Background:
    Given a Django 5.0+ project with PostgreSQL as the database backend
    And pg_2fapi is installed in the PostgreSQL database
    And the Django application has a model "Invoice" with a "client_id" field
    And RLS is enabled on the invoices table:
      """sql
      ALTER TABLE invoices ENABLE ROW LEVEL SECURITY;
      CREATE POLICY zkp_access ON invoices
        USING (client_id = twofapi.current_client());
      """

  # --- Happy Path ---

  Scenario: Django RLS integration filters queries automatically
    Given Alice is enrolled in pg_2fapi with client_id = 'alice-payments'
    And the invoices table contains rows for Alice and Bob
    And the Django middleware authenticates Alice at the start of each request:
      """python
      class ZKPAuthMiddleware:
          def __call__(self, request):
              with connection.cursor() as cursor:
                  cursor.execute(
                      "SELECT twofapi.authenticate(%s, %s, %s)",
                      [client_id, challenge_id, proof_bytes]
                  )
      """
    When Alice's request queries Invoice.objects.all()
    Then Django ORM returns only Alice's invoices
    And Bob's invoices are invisible (filtered by RLS at the database level)
    And no Django queryset filter is needed for access control

  Scenario: Enrollment via Django management command
    Given a Django management command "enroll_client":
      """python
      class Command(BaseCommand):
          def handle(self, *args, **options):
              with connection.cursor() as cursor:
                  cursor.execute(
                      "SELECT twofapi.enroll(%s, %s, %s)",
                      [client_id, commitment, proof_of_possession]
                  )
      """
    When the administrator runs:
      """bash
      python manage.py enroll_client --client-id alice-payments --commitment-file alice.commitment
      """
    Then the client is enrolled in pg_2fapi
    And subsequent Django requests can authenticate as 'alice-payments'

  Scenario: Authentication in Django middleware sets transaction-scoped session
    Given Alice has a valid challenge and proof
    When the ZKP middleware calls twofapi.authenticate() in a BEGIN...COMMIT block
    Then all subsequent SQL queries within the same Django request use Alice's session
    And when the request completes and the transaction is committed
    Then the session variables are cleared (SET LOCAL scope)
    And the next request starts without any authenticated session
```

---

## Feature 4: Example — Express + redis-2fapi (3 scenarios)

```gherkin
Feature: Express Integration Example with redis-2fapi
  As an Express.js developer
  I want a working example of Express with redis-2fapi for API authentication
  So that I can add ZKP authentication to my Redis-backed API

  Background:
    Given an Express.js application using ioredis as the Redis client
    And redis-2fapi module is loaded in the Redis server
    And the application stores session data in Redis keys prefixed by client_id

  # --- Happy Path ---

  Scenario: Express app with Redis ZKP authentication flow
    Given the Express application has an authentication middleware:
      """javascript
      async function zkpAuth(req, res, next) {
        const { clientId, challengeId, proofHex } = req.headers;
        const result = await redis.call('2FAPI.VERIFY', clientId, challengeId, proofHex);
        if (result === 'OK') {
          req.authenticatedClient = clientId;
          next();
        } else {
          res.status(401).json({ error: 'Authentication failed' });
        }
      }
      """
    When a client sends a request with valid ZKP headers
    Then the middleware verifies the proof via 2FAPI.VERIFY
    And the request proceeds to the route handler with req.authenticatedClient set
    And the route handler can access Redis keys scoped to the authenticated client

  Scenario: Enrollment endpoint registers new API clients
    Given the Express application has an enrollment endpoint:
      """javascript
      app.post('/api/enroll', async (req, res) => {
        const { clientId, commitmentHex } = req.body;
        await redis.call('2FAPI.ENROLL', clientId, commitmentHex);
        res.json({ status: 'enrolled', clientId });
      });
      """
    When a new client sends a POST to /api/enroll with their commitment
    Then redis-2fapi stores the commitment
    And the client receives a success response
    And they can subsequently request challenges via the challenge endpoint

  Scenario: Protected routes require ZKP authentication
    Given the Express application has protected routes:
      """javascript
      app.get('/api/data/:key', zkpAuth, async (req, res) => {
        const value = await redis.get(`app:${req.authenticatedClient}:${req.params.key}`);
        res.json({ key: req.params.key, value });
      });
      """
    When an unauthenticated request hits /api/data/balance
    Then the middleware returns 401 without accessing Redis data
    And when an authenticated request from 'alice-payments' hits /api/data/balance
    Then only "app:alice-payments:balance" is accessed
    And cross-client data is never exposed
```

---

## Feature 5: Migration Guide (3 scenarios)

```gherkin
Feature: Migration from Traditional Auth to 2FApi Extensions
  As a team lead
  I want step-by-step migration guides
  So that existing applications can adopt ZKP authentication incrementally

  Background:
    Given the migration follows a phased approach:
      | Phase | Description                              |
      | 1     | Install extension alongside existing auth |
      | 2     | Dual-write: both old and new auth active  |
      | 3     | Switch reads to new auth                  |
      | 4     | Remove old auth                           |
    And a rollback plan exists for each phase

  # --- Migration Path ---

  Scenario: Migrate from API keys to pg_2fapi
    Given an existing PostgreSQL application using API keys stored in a "api_keys" table
    And clients authenticate by sending their API key in an HTTP header
    When the migration is performed:
      | Step | Action                                                            |
      | 1    | Install pg_2fapi: CREATE EXTENSION pg_2fapi                       |
      | 2    | Enroll existing clients: generate commitment per API key holder    |
      | 3    | Add RLS policies referencing twofapi.current_client()              |
      | 4    | Update application middleware to call twofapi.authenticate()       |
      | 5    | Run dual-auth period: accept both API key and ZKP                  |
      | 6    | Monitor: verify all clients have transitioned                      |
      | 7    | Disable API key authentication                                    |
      | 8    | Drop the api_keys table                                            |
    Then the application uses ZKP authentication exclusively
    And RLS enforces data isolation at the database level
    And no API keys are stored anywhere in the system
    And the migration can be paused or rolled back at any step

  Scenario: Migrate from Redis AUTH to redis-2fapi
    Given an existing Redis deployment using Redis AUTH (password-based)
    And clients authenticate with "AUTH <password>" at connection time
    When the migration is performed:
      | Step | Action                                                            |
      | 1    | Load redis-2fapi: MODULE LOAD libredis_2fapi.so                   |
      | 2    | Enroll existing clients with Pedersen commitments                  |
      | 3    | Update client libraries to use 2FAPI.CHALLENGE + 2FAPI.VERIFY     |
      | 4    | Run dual-auth period: accept both AUTH and 2FAPI                   |
      | 5    | Monitor: verify all clients use 2FAPI commands                     |
      | 6    | Require 2FAPI for all connections                                  |
      | 7    | Remove Redis AUTH password                                         |
    Then the deployment uses ZKP authentication exclusively
    And no shared secrets (passwords) are stored on the server
    And per-client key isolation replaces the global AUTH model
    And the migration can be paused or rolled back at any step

  # --- Rollback ---

  Scenario: Rollback plan restores previous authentication
    Given the migration has reached phase 2 (dual-auth active)
    When an issue is detected during the ZKP migration
    Then the rollback procedure is:
      | Step | Action                                                  |
      | 1    | Disable ZKP authentication in middleware                 |
      | 2    | Re-enable API key / AUTH as the sole authentication      |
      | 3    | Remove RLS policies (pg) or unload module (redis)        |
      | 4    | Verify all clients reconnect with old authentication     |
      | 5    | DROP EXTENSION pg_2fapi CASCADE or MODULE UNLOAD 2fapi   |
    And client data is preserved throughout the rollback
    And no data loss occurs
    And the rollback completes within a maintenance window (< 1 hour)
```

---

## TDD Implementation Order

The implementation follows outside-in TDD with baby steps. Each step is a RED-GREEN-REFACTOR cycle.

### Phase 1: PostgreSQL Packaging
1. Test that `cargo pgrx package` produces a .deb file for PostgreSQL 16
2. Test that the .deb contains pg_2fapi.so, pg_2fapi.control, and pg_2fapi--1.0.sql
3. Test that dpkg -i installs cleanly on a Ubuntu 22.04 container
4. Test that dpkg -i installs cleanly on a Ubuntu 24.04 container
5. Test that CREATE EXTENSION pg_2fapi succeeds after package install (PG 16)
6. Test that CREATE EXTENSION pg_2fapi succeeds on PostgreSQL 14
7. Test that CREATE EXTENSION pg_2fapi succeeds on PostgreSQL 15
8. Test that Docker image builds and CREATE EXTENSION works in container
9. Test that META.json passes PGXN validation

### Phase 2: Redis Packaging
10. Test that `cargo build --release` produces libredis_2fapi.so
11. Test that the .so file exports RedisModule_OnLoad symbol
12. Test that MODULE LOAD succeeds on Redis 7.0
13. Test that MODULE LOAD succeeds on Redis 7.2
14. Test that MODULE LOAD succeeds on Redis 7.4
15. Test that Docker image builds and 2FAPI.STATUS works in container
16. Test that module loads alongside Redis Stack modules without conflict

### Phase 3: Django Example
17. Test that Django management command enrolls a client via twofapi.enroll()
18. Test that Django middleware calls twofapi.authenticate() and sets session
19. Test that Django ORM query returns only rows matching twofapi.current_client() via RLS
20. Test that session is cleared after Django request completes (transaction boundary)

### Phase 4: Express Example
21. Test that POST /api/enroll calls 2FAPI.ENROLL and returns success
22. Test that GET /api/challenge calls 2FAPI.CHALLENGE and returns challenge_id + nonce
23. Test that zkpAuth middleware calls 2FAPI.VERIFY and sets req.authenticatedClient on OK
24. Test that zkpAuth middleware returns 401 when 2FAPI.VERIFY returns DENIED
25. Test that protected route accesses only keys prefixed with authenticated client_id

### Phase 5: Migration Guides
26. Test that pg_2fapi can be installed alongside an existing api_keys table (no conflicts)
27. Test that dual-auth middleware accepts both API key and ZKP proof
28. Test that disabling ZKP falls back to API key auth cleanly (rollback phase 1)
29. Test that redis-2fapi MODULE LOAD works on a server with existing AUTH password
30. Test that DROP EXTENSION pg_2fapi CASCADE removes all objects without affecting app tables
31. Test that MODULE UNLOAD 2fapi removes commands without affecting existing Redis data
