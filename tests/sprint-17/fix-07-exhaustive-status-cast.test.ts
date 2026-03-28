// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PgCommitmentLookup } from "../../src/zk-verification/infrastructure/adapter/outgoing/pg-commitment-lookup.js";
import { PgCredentialVerifier } from "../../src/authentication-challenge/infrastructure/adapter/outgoing/pg-credential-verifier.js";

/**
 * Sprint 17 — Finding 7 (LOW): Non-Exhaustive Status Cast in PG Bridges
 *
 * Database bridge adapters were casting row.status directly to a union type
 * without validation. Unknown status values from the DB would silently
 * pass through. Fix: explicitly map known values, default to "unknown".
 */

describe("Exhaustive Status Handling in PG Bridges", () => {
  describe("PgCommitmentLookup", () => {
    it("should map 'active' status correctly", async () => {
      const db = {
        query: async () => ({
          rows: [{ commitment: Buffer.alloc(32, 0xaa), status: "active" }],
        }),
      };
      const lookup = new PgCommitmentLookup(db);
      const result = await lookup.findByClientIdentifier("client-1");
      expect(result).not.toBeNull();
      expect(result!.clientStatus).toBe("active");
    });

    it("should map 'revoked' status correctly", async () => {
      const db = {
        query: async () => ({
          rows: [{ commitment: Buffer.alloc(32, 0xbb), status: "revoked" }],
        }),
      };
      const lookup = new PgCommitmentLookup(db);
      const result = await lookup.findByClientIdentifier("client-2");
      expect(result).not.toBeNull();
      expect(result!.clientStatus).toBe("revoked");
    });

    it("should map unknown status to 'unknown'", async () => {
      const db = {
        query: async () => ({
          rows: [{ commitment: Buffer.alloc(32, 0xcc), status: "pending_activation" }],
        }),
      };
      const lookup = new PgCommitmentLookup(db);
      const result = await lookup.findByClientIdentifier("client-3");
      expect(result).not.toBeNull();
      expect(result!.clientStatus).toBe("unknown");
    });

    it("should map unexpected numeric status to 'unknown'", async () => {
      const db = {
        query: async () => ({
          rows: [{ commitment: Buffer.alloc(32, 0xdd), status: "42" }],
        }),
      };
      const lookup = new PgCommitmentLookup(db);
      const result = await lookup.findByClientIdentifier("client-4");
      expect(result).not.toBeNull();
      expect(result!.clientStatus).toBe("unknown");
    });

    it("should map 'suspended' status correctly", async () => {
      const db = {
        query: async () => ({
          rows: [{ commitment: Buffer.alloc(32, 0xee), status: "suspended" }],
        }),
      };
      const lookup = new PgCommitmentLookup(db);
      const result = await lookup.findByClientIdentifier("client-5");
      expect(result).not.toBeNull();
      // For CommitmentLookup, "suspended" is not in the valid set (active|revoked|unknown)
      // It should be mapped based on the domain port's valid statuses
      expect(["active", "revoked", "unknown"]).toContain(result!.clientStatus);
    });
  });

  describe("PgCredentialVerifier", () => {
    it("should map 'active' status correctly", async () => {
      const db = {
        query: async () => ({
          rows: [{ identifier: "client-1", status: "active" }],
        }),
      };
      const verifier = new PgCredentialVerifier(db);
      const result = await verifier.verify("client-1", new Uint8Array());
      expect(result.clientStatus).toBe("active");
      expect(result.valid).toBe(true);
    });

    it("should map 'revoked' status correctly", async () => {
      const db = {
        query: async () => ({
          rows: [{ identifier: "client-2", status: "revoked" }],
        }),
      };
      const verifier = new PgCredentialVerifier(db);
      const result = await verifier.verify("client-2", new Uint8Array());
      expect(result.clientStatus).toBe("revoked");
      expect(result.valid).toBe(false);
    });

    it("should map unknown status to 'unknown'", async () => {
      const db = {
        query: async () => ({
          rows: [{ identifier: "client-3", status: "pending_activation" }],
        }),
      };
      const verifier = new PgCredentialVerifier(db);
      const result = await verifier.verify("client-3", new Uint8Array());
      expect(result.clientStatus).toBe("unknown");
      expect(result.valid).toBe(false);
    });

    it("should map empty string status to 'unknown'", async () => {
      const db = {
        query: async () => ({
          rows: [{ identifier: "client-4", status: "" }],
        }),
      };
      const verifier = new PgCredentialVerifier(db);
      const result = await verifier.verify("client-4", new Uint8Array());
      expect(result.clientStatus).toBe("unknown");
      expect(result.valid).toBe(false);
    });
  });
});
