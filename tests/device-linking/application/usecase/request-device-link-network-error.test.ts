// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { RequestDeviceLinkUseCase } from "../../../../src/device-linking/application/usecase/request-device-link.usecase.js";
import { VerifyDeviceLinkUseCase } from "../../../../src/device-linking/application/usecase/verify-device-link.usecase.js";
import { LinkRequest } from "../../../../src/device-linking/domain/model/link-request.js";
import { LinkId } from "../../../../src/device-linking/domain/model/link-id.js";
import { LinkHash } from "../../../../src/device-linking/domain/model/link-hash.js";
import type { LinkRequestStore } from "../../../../src/device-linking/domain/port/outgoing/link-request-store.js";

const failingStore: LinkRequestStore = {
  async save() { throw new Error("NETWORK_UNREACHABLE"); },
  async findByClientId() { throw new Error("NETWORK_UNREACHABLE"); },
  async findByHash() { throw new Error("NETWORK_UNREACHABLE"); },
  async deleteByClientId() { throw new Error("NETWORK_UNREACHABLE"); },
  async compareAndSave() { throw new Error("NETWORK_UNREACHABLE"); },
};

const NOW = 1711540000000;

describe("Network error — server unreachable during linking", () => {
  it("propagates store error on link request creation", async () => {
    const useCase = new RequestDeviceLinkUseCase({
      linkRequestStore: failingStore,
      randomHex: () => "abc",
      randomIndex: () => 742,
      nowMs: () => Date.now(),
      validateSession: async () => true,
    });

    await expect(
      useCase.execute({ clientId: "alice", sessionId: "s1" }),
    ).rejects.toThrow("NETWORK_UNREACHABLE");
  });

  it("propagates store error on verification without counting attempt", async () => {
    const useCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: failingStore,
      nowMs: () => Date.now(),
    });

    await expect(
      useCase.execute({ clientId: "alice", hashHex: "abc" }),
    ).rejects.toThrow("NETWORK_UNREACHABLE");
  });

  it("retry succeeds after network error without lost attempt (#48)", async () => {
    const hash = LinkHash.fromWords(["gold", "tiger", "blind", "sail"]);
    const hashHex = Buffer.from(hash.bytes).toString("hex");
    const request = LinkRequest.create({
      id: LinkId.from("lk-test"),
      hash,
      clientId: "alice",
      createdAt: NOW,
      ttlMs: 60_000,
    });

    let failNext = true;
    let stored: LinkRequest | null = request;

    const flakeyStore: LinkRequestStore = {
      async save(r: LinkRequest) { stored = r; },
      async findByClientId() {
        if (failNext) throw new Error("NETWORK_UNREACHABLE");
        return stored;
      },
      async findByHash() { return stored; },
      async deleteByClientId() { stored = null; },
      async compareAndSave() { return true; },
    };

    const useCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: flakeyStore,
      nowMs: () => NOW + 5_000,
    });

    // First attempt: network error (should not count)
    await expect(
      useCase.execute({ clientId: "alice", hashHex }),
    ).rejects.toThrow("NETWORK_UNREACHABLE");

    // Network recovers
    failNext = false;

    // Retry: should succeed (attempt not counted)
    const result = await useCase.execute({ clientId: "alice", hashHex });
    expect(result.status).toBe("success");
  });
});
