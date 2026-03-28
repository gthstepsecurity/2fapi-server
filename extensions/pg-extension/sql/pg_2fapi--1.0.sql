-- Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
-- Licensed under the Business Source License 1.1. See LICENSE for details.
-- pg_2fapi: Zero-Knowledge Proof authentication for PostgreSQL
-- Extension SQL — executed by CREATE EXTENSION pg_2fapi
--
-- The schema "twofapi" is created automatically by the .control file
-- (schema = twofapi). Do NOT create it here.
--
-- SECURITY: All SECURITY DEFINER functions SET search_path to prevent
-- privilege escalation via malicious objects in public schema (PG-070/091/092).

-- ============================================================
-- Admin role (FIX C3)
-- ============================================================

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'twofapi_admin') THEN
        CREATE ROLE twofapi_admin NOLOGIN;
    END IF;
END
$$;

-- ============================================================
-- Internal tables
-- ============================================================

CREATE TABLE IF NOT EXISTS twofapi.clients (
    client_id TEXT PRIMARY KEY,
    commitment BYTEA NOT NULL CHECK (length(commitment) = 32),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    commitment_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now()
);

CREATE TABLE IF NOT EXISTS twofapi.challenges (
    challenge_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES twofapi.clients(client_id),
    nonce BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_challenges_client ON twofapi.challenges(client_id);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON twofapi.challenges(expires_at);

-- Audit log table (FIX M5) — capped at reasonable size via periodic cleanup
CREATE TABLE IF NOT EXISTS twofapi.audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    operation TEXT NOT NULL,
    client_id TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    client_addr TEXT DEFAULT pg_catalog.inet_client_addr()::text,
    backend_pid INTEGER DEFAULT pg_catalog.pg_backend_pid()
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON twofapi.audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_client ON twofapi.audit_log(client_id) WHERE client_id != '';

-- ============================================================
-- Permissions (FIX C3)
-- ============================================================

REVOKE ALL ON twofapi.clients FROM PUBLIC;
REVOKE ALL ON twofapi.challenges FROM PUBLIC;
REVOKE ALL ON twofapi.audit_log FROM PUBLIC;
REVOKE ALL ON SEQUENCE twofapi.audit_log_id_seq FROM PUBLIC;

GRANT SELECT ON twofapi.audit_log TO twofapi_admin;

-- ============================================================
-- SQL function declarations
-- SECURITY: Every SECURITY DEFINER function has SET search_path
-- to prevent search_path hijacking (PG-070/091/092).
-- ============================================================

-- Extension version (IMMUTABLE, no SECURITY DEFINER needed)
CREATE OR REPLACE FUNCTION twofapi.version()
    RETURNS TEXT
    STRICT IMMUTABLE
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'version_wrapper';

-- Client enrollment
CREATE OR REPLACE FUNCTION twofapi.enroll(
    client_id TEXT,
    commitment BYTEA,
    proof BYTEA
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'enroll_wrapper';

-- Issue a challenge
CREATE OR REPLACE FUNCTION twofapi.issue_challenge(
    client_id TEXT
) RETURNS TEXT
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'issue_challenge_wrapper';

-- Get nonce (requires client_id for ownership verification)
CREATE OR REPLACE FUNCTION twofapi.get_challenge_nonce(
    client_id TEXT,
    challenge_id TEXT
) RETURNS BYTEA
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'get_challenge_nonce_wrapper';

-- Verify a ZKP proof
CREATE OR REPLACE FUNCTION twofapi.verify(
    client_id TEXT,
    challenge_id TEXT,
    proof BYTEA
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'verify_wrapper';

-- Verify with channel binding
CREATE OR REPLACE FUNCTION twofapi.verify_with_binding(
    client_id TEXT,
    challenge_id TEXT,
    proof BYTEA,
    channel_binding BYTEA
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'verify_with_binding_wrapper';

-- Authenticate: verify + establish session
CREATE OR REPLACE FUNCTION twofapi.authenticate(
    client_id TEXT,
    challenge_id TEXT,
    proof BYTEA
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'authenticate_wrapper';

-- Get authenticated client (from Rust memory, not GUC)
CREATE OR REPLACE FUNCTION twofapi.current_client()
    RETURNS TEXT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'current_client_wrapper';

-- Admin: cleanup expired challenges + old audit log entries
-- audit_retention_days: keep N days of audit log (default 30, range 1-365)
CREATE OR REPLACE FUNCTION twofapi.cleanup(
    audit_retention_days INTEGER DEFAULT 30
) RETURNS BIGINT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'cleanup_wrapper';

-- Backward-compatible alias (calls cleanup with default 30 days)
CREATE OR REPLACE FUNCTION twofapi.cleanup_expired_challenges()
    RETURNS BIGINT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'cleanup_expired_challenges_wrapper';

-- Admin: suspend a client
CREATE OR REPLACE FUNCTION twofapi.suspend_client(
    client_id TEXT
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'suspend_client_wrapper';

-- Admin: revoke a client permanently
CREATE OR REPLACE FUNCTION twofapi.revoke_client(
    client_id TEXT
) RETURNS BOOLEAN
    STRICT
    SECURITY DEFINER
    SET search_path = twofapi, pg_catalog
    LANGUAGE c
    AS 'MODULE_PATHNAME', 'revoke_client_wrapper';

-- ============================================================
-- GRANT/REVOKE on functions
-- ============================================================

-- User-facing functions
GRANT EXECUTE ON FUNCTION twofapi.version() TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.enroll(TEXT, BYTEA, BYTEA) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.issue_challenge(TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.get_challenge_nonce(TEXT, TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.verify(TEXT, TEXT, BYTEA) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.verify_with_binding(TEXT, TEXT, BYTEA, BYTEA) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.authenticate(TEXT, TEXT, BYTEA) TO PUBLIC;
GRANT EXECUTE ON FUNCTION twofapi.current_client() TO PUBLIC;

-- Admin functions — REVOKE from PUBLIC first, then GRANT to admin only
REVOKE EXECUTE ON FUNCTION twofapi.cleanup(INTEGER) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION twofapi.cleanup_expired_challenges() FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION twofapi.suspend_client(TEXT) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION twofapi.revoke_client(TEXT) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION twofapi.cleanup(INTEGER) TO twofapi_admin;
GRANT EXECUTE ON FUNCTION twofapi.cleanup_expired_challenges() TO twofapi_admin;
GRANT EXECUTE ON FUNCTION twofapi.suspend_client(TEXT) TO twofapi_admin;
GRANT EXECUTE ON FUNCTION twofapi.revoke_client(TEXT) TO twofapi_admin;

-- ============================================================
-- Documentation
-- ============================================================

COMMENT ON SCHEMA twofapi IS
    '2FApi: Zero-Knowledge Proof authentication for PostgreSQL.

    Security model:
    - All functions run with SECURITY DEFINER + SET search_path
    - Internal tables are not directly accessible (REVOKE ALL FROM PUBLIC)
    - Admin functions require twofapi_admin role
    - Session state is in Rust process memory (immune to GUC spoofing)

    Quick start:
    1. SELECT twofapi.enroll(''my-service'', commitment_bytes, proof_bytes);
    2. SELECT twofapi.issue_challenge(''my-service'');
    3. SELECT twofapi.get_challenge_nonce(''my-service'', ''ch-abc123'');
    4. SELECT twofapi.authenticate(''my-service'', ''ch-abc123'', proof_bytes);
    5. CREATE POLICY zkp ON my_data USING (owner = twofapi.current_client());

    Admin (requires: GRANT twofapi_admin TO your_user):
    - SELECT twofapi.suspend_client(''my-service'');
    - SELECT twofapi.revoke_client(''my-service'');
    - SELECT twofapi.cleanup_expired_challenges();';
