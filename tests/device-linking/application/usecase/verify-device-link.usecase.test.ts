// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import { VerifyDeviceLinkUseCase } from "../../../../src/device-linking/application/usecase/verify-device-link.usecase.js";
import type { LinkRequestStore } from "../../../../src/device-linking/domain/port/outgoing/link-request-store.js";
import { LinkRequest } from "../../../../src/device-linking/domain/model/link-request.js";
import { LinkId } from "../../../../src/device-linking/domain/model/link-id.js";
import { LinkHash } from "../../../../src/device-linking/domain/model/link-hash.js";

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
  async compareAndSave(
    clientId: string,
    expectedStatus: string,
    request: LinkRequest,
  ): Promise<boolean> {
    const current = this.store.get(clientId);
    if (current && current.status === expectedStatus) {
      this.store.set(clientId, request);
      return true;
    }
    return false;
  }
}

describe("VerifyDeviceLinkUseCase", () => {
  const NOW = 1711540000000;
  let store: InMemoryLinkRequestStore;
  let useCase: VerifyDeviceLinkUseCase;

  function makeRequest(overrides?: { createdAt?: number }): LinkRequest {
    const id = LinkId.generate(() => "abc123");
    const hash = LinkHash.fromWords(["gold", "tiger", "blind", "sail"]);
    return LinkRequest.create({
      id, hash, clientId: "alice",
      createdAt: overrides?.createdAt ?? NOW,
      ttlMs: 60_000,
    });
  }

  beforeEach(() => {
    store = new InMemoryLinkRequestStore();
    useCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: store,
      nowMs: () => NOW + 10_000, // 10s after creation — within TTL
    });
  });

  it("succeeds when hash matches and request is not expired", async () => {
    const request = makeRequest();
    await store.save(request);
    const correctHashHex = Buffer.from(request.hash.bytes).toString("hex");

    const result = await useCase.execute({ clientId: "alice", hashHex: correctHashHex });
    expect(result.status).toBe("success");

    const updated = await store.findByClientId("alice");
    expect(updated!.status).toBe("pending_confirmation");
  });

  // FIX Mitnick: all failure paths now return "refused" (was: hash_mismatch, not_found, etc.)
  it("returns refused on wrong hash and increments attempts", async () => {
    const request = makeRequest();
    await store.save(request);

    const result = await useCase.execute({ clientId: "alice", hashHex: "0000dead" });
    expect(result.status).toBe("refused");

    const updated = await store.findByClientId("alice");
    expect(updated!.attemptCount).toBe(1);
  });

  it("returns refused after exhausted attempts and deletes request", async () => {
    let request = makeRequest();
    request = request.recordFailedAttempt().recordFailedAttempt().recordFailedAttempt();
    await store.save(request);

    const result = await useCase.execute({ clientId: "alice", hashHex: "anything" });
    expect(result.status).toBe("refused");

    const stored = await store.findByClientId("alice");
    expect(stored).toBeNull();
  });

  it("returns refused when TTL has passed", async () => {
    const request = makeRequest({ createdAt: NOW - 70_000 });
    await store.save(request);
    const correctHashHex = Buffer.from(request.hash.bytes).toString("hex");

    const expiredUseCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: store,
      nowMs: () => NOW,
    });

    const result = await expiredUseCase.execute({ clientId: "alice", hashHex: correctHashHex });
    expect(result.status).toBe("refused");
  });

  it("returns refused when no link request exists", async () => {
    const result = await useCase.execute({ clientId: "alice", hashHex: "abc" });
    expect(result.status).toBe("refused");
  });

  // Mitnick: refused does NOT reveal attempt count
  it("refused response does not contain attemptsRemaining", async () => {
    const request = makeRequest();
    await store.save(request);

    const result = await useCase.execute({ clientId: "alice", hashHex: "wrong" });
    expect(result.status).toBe("refused");
    expect("attemptsRemaining" in result).toBe(false);
  });

  // Mitnick: all failure statuses are identical
  it("not_found and hash_mismatch return the same status string", async () => {
    // not_found path
    const r1 = await useCase.execute({ clientId: "unknown", hashHex: "abc" });
    // hash_mismatch path
    const request = makeRequest();
    await store.save(request);
    const r2 = await useCase.execute({ clientId: "alice", hashHex: "wrong" });

    expect(r1.status).toBe(r2.status);
    expect(r1.status).toBe("refused");
  });
});
