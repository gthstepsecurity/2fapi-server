// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { RequestDeviceLinkUseCase } from "../../../../src/device-linking/application/usecase/request-device-link.usecase.js";
import type { LinkRequestStore } from "../../../../src/device-linking/domain/port/outgoing/link-request-store.js";
import type { LinkRequest } from "../../../../src/device-linking/domain/model/link-request.js";

class InMemoryLinkRequestStore implements LinkRequestStore {
  private readonly store = new Map<string, LinkRequest>();

  async save(request: LinkRequest): Promise<void> {
    this.store.set(request.clientId, request);
  }

  async findByClientId(clientId: string): Promise<LinkRequest | null> {
    return this.store.get(clientId) ?? null;
  }

  async findByHash(_hashHex: string): Promise<LinkRequest | null> {
    for (const req of this.store.values()) {
      if (Buffer.from(req.hash.bytes).toString("hex") === _hashHex) return req;
    }
    return null;
  }

  async deleteByClientId(clientId: string): Promise<void> {
    this.store.delete(clientId);
  }
}

describe("RequestDeviceLinkUseCase", () => {
  let store: InMemoryLinkRequestStore;
  let useCase: RequestDeviceLinkUseCase;
  let callCount: number;

  beforeEach(() => {
    store = new InMemoryLinkRequestStore();
    callCount = 0;
    let indexCounter = 0;
    useCase = new RequestDeviceLinkUseCase({
      linkRequestStore: store,
      randomHex: () => `hex${++callCount}`,
      randomIndex: () => 100 + (++indexCounter),
      nowMs: () => 1711540000000,
      validateSession: async () => true,
    });
  });

  it("invalidates previous request when creating a new one for same client", async () => {
    // First request
    const r1 = await useCase.execute({ clientId: "alice", sessionId: "s1" });

    // Second request — should replace the first
    const r2 = await useCase.execute({ clientId: "alice", sessionId: "s1" });

    expect(r1.linkId).not.toBe(r2.linkId);

    const stored = await store.findByClientId("alice");
    expect(stored).not.toBeNull();
    expect(stored!.id.value).toBe(r2.linkId);
  });

  it("returns linkId and 4 indexes, and stores the request", async () => {
    const result = await useCase.execute({ clientId: "alice", sessionId: "s1" });

    expect(result.linkId).toMatch(/^lk-/);
    expect(result.indexes).toHaveLength(6);
    for (const idx of result.indexes) {
      expect(idx).toBeGreaterThanOrEqual(1);
    }

    const stored = await store.findByClientId("alice");
    expect(stored).not.toBeNull();
    expect(stored!.clientId).toBe("alice");
    expect(stored!.hash.bytes).toHaveLength(64);
  });

  it("old link request hash is not findable after regeneration", async () => {
    const r1 = await useCase.execute({ clientId: "alice", sessionId: "s1" });

    // Get L1's hash
    const l1 = await store.findByClientId("alice");
    const l1HashHex = Buffer.from(l1!.hash.bytes).toString("hex");

    // Regenerate — L1 should be gone
    await useCase.execute({ clientId: "alice", sessionId: "s1" });

    const found = await store.findByHash(l1HashHex);
    expect(found).toBeNull();
  });

  it("rejects unauthenticated requests", async () => {
    const unauthUseCase = new RequestDeviceLinkUseCase({
      linkRequestStore: store,
      randomHex: () => "hex1",
      randomIndex: () => 100,
      nowMs: () => 1711540000000,
      validateSession: async () => false,
    });

    await expect(
      unauthUseCase.execute({ clientId: "alice", sessionId: "invalid" }),
    ).rejects.toThrow("UNAUTHENTICATED");

    const stored = await store.findByClientId("alice");
    expect(stored).toBeNull();
  });
});
