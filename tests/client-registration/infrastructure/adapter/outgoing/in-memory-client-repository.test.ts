// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InMemoryClientRepository } from "../../../../../src/client-registration/infrastructure/adapter/outgoing/in-memory-client-repository.js";
import { Client } from "../../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../../src/client-registration/domain/model/commitment.js";

function createClient(
  identifier: string = "client-1",
  idByte: number = 1,
  commitmentByte: number = 42,
): Client {
  const id = ClientId.fromBytes(new Uint8Array(16).fill(idByte));
  const commitment = Commitment.fromBytes(new Uint8Array(32).fill(commitmentByte));
  return Client.register(id, identifier, commitment);
}

describe("InMemoryClientRepository", () => {
  it("saves and retrieves a client by identifier", async () => {
    const repository = new InMemoryClientRepository();
    const client = createClient("client-1");

    await repository.save(client);
    const found = await repository.findByIdentifier("client-1");

    expect(found).not.toBeNull();
    expect(found!.identifier).toBe("client-1");
  });

  it("returns null when client not found", async () => {
    const repository = new InMemoryClientRepository();

    const found = await repository.findByIdentifier("nonexistent");

    expect(found).toBeNull();
  });

  it("returns true for existsByIdentifier when client exists", async () => {
    const repository = new InMemoryClientRepository();
    await repository.save(createClient("client-1"));

    const exists = await repository.existsByIdentifier("client-1");

    expect(exists).toBe(true);
  });

  it("returns false for existsByIdentifier when client does not exist", async () => {
    const repository = new InMemoryClientRepository();

    const exists = await repository.existsByIdentifier("nonexistent");

    expect(exists).toBe(false);
  });

  it("throws on version conflict when saving same identifier twice", async () => {
    const repository = new InMemoryClientRepository();
    const client1 = createClient("client-1", 1, 42);
    const client2 = createClient("client-1", 2, 99);

    await repository.save(client1);

    await expect(repository.save(client2)).rejects.toThrow(
      "Optimistic concurrency conflict",
    );
  });

  it("updates an existing client", async () => {
    const repository = new InMemoryClientRepository();
    const client = createClient("client-1");
    await repository.save(client);

    const revoked = client.revoke();
    await repository.update(revoked);

    const found = await repository.findByIdentifier("client-1");
    expect(found!.status).toBe("revoked");
  });

  it("throws when updating a client that does not exist", async () => {
    const repository = new InMemoryClientRepository();
    const client = createClient("nonexistent");

    await expect(repository.update(client)).rejects.toThrow(
      "Client not found for update",
    );
  });
});
