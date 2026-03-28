// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CredentialVerifier,
  CredentialVerificationResult,
} from "../../../domain/port/outgoing/credential-verifier.js";

/**
 * Minimal database client interface (subset of pg.Pool / pg.PoolClient).
 */
export interface DatabaseClient {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>;
}

/**
 * Row shape from the clients table (subset for credential verification).
 */
interface ClientRow {
  identifier: string;
  status: string;
}

/**
 * PostgreSQL-backed credential verifier for the Authentication Challenge context.
 *
 * Cross-context bridge: queries the clients table (owned by Client Registration)
 * to verify that a client exists and is active. In the ZKP protocol, the "credential"
 * is the client identifier itself — the first factor is "something you have" (the API key
 * or client ID), while the second factor is the zero-knowledge proof.
 *
 * This adapter verifies the first factor by checking client existence and status.
 */
export class PgCredentialVerifier implements CredentialVerifier {
  constructor(private readonly db: DatabaseClient) {}

  async verify(clientIdentifier: string, _credential: Uint8Array): Promise<CredentialVerificationResult> {
    try {
      const result = await this.db.query(
        "SELECT identifier, status FROM clients WHERE identifier = $1",
        [clientIdentifier],
      );

      if (result.rows.length === 0) {
        return {
          valid: false,
          clientIdentifier,
          clientStatus: "unknown",
          isLegacyApiKey: false,
        };
      }

      const row = result.rows[0] as ClientRow;
      const knownStatuses = new Set(["active", "revoked"]);
      const status: "active" | "revoked" | "unknown" = knownStatuses.has(row.status)
        ? (row.status as "active" | "revoked")
        : "unknown";

      return {
        valid: status === "active",
        clientIdentifier: row.identifier,
        clientStatus: status,
        isLegacyApiKey: false,
      };
    } catch {
      // Database errors are treated as verification failure (fail-closed)
      return {
        valid: false,
        clientIdentifier,
        clientStatus: "unknown",
        isLegacyApiKey: false,
      };
    }
  }
}
