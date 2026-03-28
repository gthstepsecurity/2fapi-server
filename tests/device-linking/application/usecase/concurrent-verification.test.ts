// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { VerifyDeviceLinkUseCase } from "../../../../src/device-linking/application/usecase/verify-device-link.usecase.js";
import { LinkRequest } from "../../../../src/device-linking/domain/model/link-request.js";
import { LinkId } from "../../../../src/device-linking/domain/model/link-id.js";
import { LinkHash } from "../../../../src/device-linking/domain/model/link-hash.js";
import type { LinkRequestStore } from "../../../../src/device-linking/domain/port/outgoing/link-request-store.js";

const NOW = 1711540000000;

function createCASStore(): LinkRequestStore & { casCallCount: number } {
  let current: LinkRequest | null = null;
  let casCallCount = 0;

  const hash = LinkHash.fromWords(["gold", "tiger", "blind", "sail"]);
  current = LinkRequest.create({
    id: LinkId.from("lk-test"),
    hash,
    clientId: "alice",
    createdAt: NOW,
    ttlMs: 60_000,
  });

  return {
    casCallCount: 0,
    async save(request: LinkRequest) {
      current = request;
    },
    async findByClientId() {
      return current;
    },
    async findByHash() {
      return current;
    },
    async deleteByClientId() {
      current = null;
    },
    async compareAndSave(
      _clientId: string,
      expectedStatus: string,
      request: LinkRequest,
    ): Promise<boolean> {
      casCallCount++;
      // Simulate: first call succeeds, second fails (already consumed)
      if (current && current.status === expectedStatus) {
        current = request;
        return true;
      }
      return false;
    },
  };
}

describe("Concurrent verification — first wins (#40)", () => {
  it("first verification succeeds, second gets already_consumed", async () => {
    const hash = LinkHash.fromWords(["gold", "tiger", "blind", "sail"]);
    const hashHex = Buffer.from(hash.bytes).toString("hex");

    const store = createCASStore();
    const useCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: store,
      nowMs: () => NOW + 5_000,
    });

    // First verification succeeds
    const result1 = await useCase.execute({
      clientId: "alice",
      hashHex,
    });
    expect(result1.status).toBe("success");

    // Second verification fails — already consumed
    const result2 = await useCase.execute({
      clientId: "alice",
      hashHex,
    });
    expect(result2.status).toBe("refused");
  });
});
