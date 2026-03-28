// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { PgClientRepository, type DatabaseClient } from "../../src/client-registration/infrastructure/adapter/outgoing/pg-client-repository.js";
import { Client } from "../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../src/client-registration/domain/model/commitment.js";

/**
 * In-memory database client that simulates PostgreSQL for testing.
 */
function createInMemoryDb(): DatabaseClient & { rows: Map<string, Record<string, unknown>> } {
  const rows = new Map<string, Record<string, unknown>>();
  return {
    rows,
    async query(text: string, values?: unknown[]): Promise<{ rows: unknown[]; rowCount: number | null }> {
      if (text.startsWith("INSERT INTO clients")) {
        const identifier = values![1] as string;
        rows.set(identifier, {
          id: values![0] as Buffer,
          identifier: values![1] as string,
          commitment: values![2] as Buffer,
          status: values![3] as string,
          commitment_version: values![4] as number,
          created_at: values![5] as number,
          updated_at: values![6] as number,
        });
        return { rows: [], rowCount: 1 };
      }
      if (text.startsWith("UPDATE clients")) {
        const identifier = values![4] as string;
        const existing = rows.get(identifier);
        if (!existing) return { rows: [], rowCount: 0 };
        existing.commitment = values![0] as Buffer;
        existing.status = values![1] as string;
        existing.commitment_version = values![2] as number;
        existing.updated_at = values![3] as number;
        return { rows: [], rowCount: 1 };
      }
      if (text.startsWith("SELECT id, identifier, commitment, status, commitment_version")) {
        const identifier = values![0] as string;
        const row = rows.get(identifier);
        if (!row) return { rows: [], rowCount: 0 };
        return { rows: [row], rowCount: 1 };
      }
      if (text.startsWith("SELECT 1 FROM clients")) {
        const identifier = values![0] as string;
        return rows.has(identifier)
          ? { rows: [{ "1": 1 }], rowCount: 1 }
          : { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

describe("FIX 5 — commitmentVersion Persistence in PgClientRepository", () => {
  it("saves client with commitmentVersion and restores it correctly", async () => {
    const db = createInMemoryDb();
    const repo = new PgClientRepository(db);

    const id = ClientId.fromBytes(new Uint8Array(16).fill(0x01));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0xaa));
    let client = Client.register(id, "alice-versioned", commitment);
    // Rotate commitment twice to get version 3
    const c2 = Commitment.fromBytes(new Uint8Array(32).fill(0xbb));
    client = client.rotateCommitment(c2);
    const c3 = Commitment.fromBytes(new Uint8Array(32).fill(0xcc));
    client = client.rotateCommitment(c3);

    expect(client.commitmentVersion).toBe(3);

    await repo.save(client);

    const restored = await repo.findByIdentifier("alice-versioned");
    expect(restored).not.toBeNull();
    expect(restored!.commitmentVersion).toBe(3);
  });

  it("updates commitmentVersion on update", async () => {
    const db = createInMemoryDb();
    const repo = new PgClientRepository(db);

    const id = ClientId.fromBytes(new Uint8Array(16).fill(0x01));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0xaa));
    const client = Client.register(id, "bob-versioned", commitment);

    await repo.save(client);

    // Rotate and update
    const c2 = Commitment.fromBytes(new Uint8Array(32).fill(0xbb));
    const rotated = client.rotateCommitment(c2);
    expect(rotated.commitmentVersion).toBe(2);

    await repo.update(rotated);

    const restored = await repo.findByIdentifier("bob-versioned");
    expect(restored).not.toBeNull();
    expect(restored!.commitmentVersion).toBe(2);
  });

  it("restores revoked client with correct version", async () => {
    const db = createInMemoryDb();
    const repo = new PgClientRepository(db);

    const id = ClientId.fromBytes(new Uint8Array(16).fill(0x01));
    const commitment = Commitment.fromBytes(new Uint8Array(32).fill(0xaa));
    let client = Client.register(id, "carol-revoked", commitment);
    const c2 = Commitment.fromBytes(new Uint8Array(32).fill(0xbb));
    client = client.rotateCommitment(c2);
    client = client.revoke();

    expect(client.commitmentVersion).toBe(2);
    expect(client.status).toBe("revoked");

    await repo.save(client);

    const restored = await repo.findByIdentifier("carol-revoked");
    expect(restored).not.toBeNull();
    expect(restored!.status).toBe("revoked");
    expect(restored!.commitmentVersion).toBe(2);
  });
});
