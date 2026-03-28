// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientRepository } from "../../../domain/port/outgoing/client-repository.js";
import type { Client } from "../../../domain/model/client.js";

export class InMemoryClientRepository implements ClientRepository {
  private readonly clients = new Map<string, Client>();

  async save(client: Client): Promise<void> {
    const existing = this.clients.get(client.identifier);
    if (existing && !existing.commitment.equals(client.commitment)) {
      throw new Error("Optimistic concurrency conflict");
    }
    this.clients.set(client.identifier, client);
  }

  async update(client: Client): Promise<void> {
    if (!this.clients.has(client.identifier)) {
      throw new Error("Client not found for update");
    }
    this.clients.set(client.identifier, client);
  }

  async findByIdentifier(identifier: string): Promise<Client | null> {
    return this.clients.get(identifier) ?? null;
  }

  async existsByIdentifier(identifier: string): Promise<boolean> {
    return this.clients.has(identifier);
  }
}
