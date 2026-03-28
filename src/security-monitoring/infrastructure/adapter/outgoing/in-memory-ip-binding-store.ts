// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { IpBindingStore } from "../../../domain/port/outgoing/ip-binding-store.js";
import type { IpBinding } from "../../../domain/model/ip-binding.js";

/**
 * In-memory implementation of IpBindingStore.
 * For testing and development only.
 */
export class InMemoryIpBindingStore implements IpBindingStore {
  private readonly bindings: IpBinding[] = [];

  async save(binding: IpBinding): Promise<void> {
    this.bindings.push(binding);
  }

  async findByClientIdentifier(clientIdentifier: string): Promise<readonly IpBinding[]> {
    return this.bindings.filter((b) => b.clientIdentifier === clientIdentifier);
  }

  async findLatestByClientIdentifier(clientIdentifier: string): Promise<IpBinding | null> {
    const filtered = this.bindings.filter((b) => b.clientIdentifier === clientIdentifier);
    return filtered.length > 0 ? filtered[filtered.length - 1] ?? null : null;
  }
}
