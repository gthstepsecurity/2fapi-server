// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PgClientRepository } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/pg-client-repository.js";
import type { DatabaseClient } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/pg-client-repository.js";

/**
 * Creates a fake DatabaseClient that returns the given rows for SELECT queries.
 */
function createFakeDb(rows: unknown[]): DatabaseClient {
  return {
    query: async () => ({ rows, rowCount: rows.length }),
  };
}

describe("PgClientRepository", () => {
  describe("toDomain — status mapping (CD06)", () => {
    it("maps 'suspended' status from DB to Client with suspended status", async () => {
      const row = {
        id: Buffer.from(new Uint8Array(16).fill(1)),
        identifier: "test-client",
        commitment: Buffer.from(new Uint8Array(32).fill(42)),
        status: "suspended",
        commitment_version: 1,
        created_at: "1000",
        updated_at: "2000",
      };
      const db = createFakeDb([row]);
      const repo = new PgClientRepository(db);

      const client = await repo.findByIdentifier("test-client");

      expect(client).not.toBeNull();
      expect(client!.status).toBe("suspended");
    });

    it("maps 'active' status from DB correctly", async () => {
      const row = {
        id: Buffer.from(new Uint8Array(16).fill(1)),
        identifier: "test-client",
        commitment: Buffer.from(new Uint8Array(32).fill(42)),
        status: "active",
        commitment_version: 1,
        created_at: "1000",
        updated_at: "2000",
      };
      const db = createFakeDb([row]);
      const repo = new PgClientRepository(db);

      const client = await repo.findByIdentifier("test-client");

      expect(client).not.toBeNull();
      expect(client!.status).toBe("active");
    });

    it("maps 'revoked' status from DB correctly", async () => {
      const row = {
        id: Buffer.from(new Uint8Array(16).fill(1)),
        identifier: "test-client",
        commitment: Buffer.from(new Uint8Array(32).fill(42)),
        status: "revoked",
        commitment_version: 1,
        created_at: "1000",
        updated_at: "2000",
      };
      const db = createFakeDb([row]);
      const repo = new PgClientRepository(db);

      const client = await repo.findByIdentifier("test-client");

      expect(client).not.toBeNull();
      expect(client!.status).toBe("revoked");
    });
  });
});
