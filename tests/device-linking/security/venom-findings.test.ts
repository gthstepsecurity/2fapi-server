// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { LinkHash } from "../../../src/device-linking/domain/model/link-hash.js";
import { RequestDeviceLinkUseCase } from "../../../src/device-linking/application/usecase/request-device-link.usecase.js";
import type { LinkRequestStore } from "../../../src/device-linking/domain/port/outgoing/link-request-store.js";
import type { LinkRequest } from "../../../src/device-linking/domain/model/link-request.js";

// ============================================================================
// VENOM-01: Cache-line oracle — word length varies → SHA-512 block padding differs
// Fix: All indexes zero-padded to 4 characters
// ============================================================================

describe("VENOM-01: Fixed-width index encoding prevents cache-line oracle", () => {
  it("indexes are zero-padded to 4 chars in hash computation", () => {
    // "1" must become "0001", "742" must become "0742"
    // The hash of padded "0001" must differ from unpadded "1"
    const padded = LinkHash.fromWords(["0001", "0742", "0203", "1544"], "salt");
    const unpadded = LinkHash.fromWords(["1", "742", "203", "1544"], "salt");

    // They MUST be different — padded is the correct encoding
    expect(padded.equals(unpadded)).toBe(false);
  });

  it("use case pads indexes to 4 chars before hashing", async () => {
    let capturedWords: string[] = [];

    // Monkey-patch LinkHash.fromWords to capture the words
    const origFromWords = LinkHash.fromWords;
    LinkHash.fromWords = function (words: readonly string[], salt?: string) {
      capturedWords = [...words];
      return origFromWords(words, salt);
    };

    const store: LinkRequestStore = {
      async save() {},
      async findByClientId() { return null; },
      async findByHash() { return null; },
      async deleteByClientId() {},
      async compareAndSave() { return true; },
    };

    // FIX: must return UNIQUE indexes — returning the same value loops forever
    let idx = 0;
    const uniqueIndexes = [1, 2, 3, 4, 5, 6, 7, 8];
    const useCase = new RequestDeviceLinkUseCase({
      linkRequestStore: store,
      randomHex: () => "abc",
      randomIndex: () => uniqueIndexes[idx++]!,
      nowMs: () => Date.now(),
      validateSession: async () => true,
    });

    await useCase.execute({ clientId: "alice", sessionId: "s1" });

    // Restore
    LinkHash.fromWords = origFromWords;

    // All words must be 4 chars wide (zero-padded)
    for (const w of capturedWords) {
      expect(w).toHaveLength(4);
      expect(w).toMatch(/^\d{4}$/);
    }
  });
});

// ============================================================================
// VENOM-02: Index collision → entropy collapse
// Fix: Generated indexes must be unique
// ============================================================================

describe("VENOM-02: Index uniqueness prevents entropy collapse", () => {
  it("use case generates unique indexes (no duplicates)", async () => {
    const store: LinkRequestStore = {
      async save() {},
      async findByClientId() { return null; },
      async findByHash() { return null; },
      async deleteByClientId() {},
      async compareAndSave() { return true; },
    };

    // randomIndex returns repeating pattern with duplicates
    // The use case must detect duplicates and regenerate
    let callCount = 0;
    const sequence = [100, 100, 200, 200, 300, 300, 400, 500, 600, 700];

    const useCase = new RequestDeviceLinkUseCase({
      linkRequestStore: store,
      randomHex: () => "abc",
      randomIndex: () => sequence[callCount++]!,
      nowMs: () => Date.now(),
      validateSession: async () => true,
    });

    const result = await useCase.execute({ clientId: "alice", sessionId: "s1" });

    // All 6 indexes must be unique (default count is now 6)
    const unique = new Set(result.indexes);
    expect(unique.size).toBe(result.indexes.length);
    expect(unique.size).toBe(6);
  });
});

// ============================================================================
// VENOM-03: verify uses save() instead of compareAndSave() → race condition
// ============================================================================

describe("VENOM-03: Verify uses atomic CAS for state transition", () => {
  it("verify uses compareAndSave to prevent concurrent verification race", async () => {
    // This test cannot directly test CAS at domain level, but we verify
    // that the verify use case rejects already-consumed requests
    // (the status check is the domain-level guard; CAS is the adapter guarantee)

    const { VerifyDeviceLinkUseCase } = await import(
      "../../../src/device-linking/application/usecase/verify-device-link.usecase.js"
    );
    const { LinkRequest } = await import(
      "../../../src/device-linking/domain/model/link-request.js"
    );
    const { LinkId } = await import(
      "../../../src/device-linking/domain/model/link-id.js"
    );
    const { LinkHash } = await import(
      "../../../src/device-linking/domain/model/link-hash.js"
    );

    const NOW = 1711540000000;
    const hash = LinkHash.fromWords(["0742", "1891", "0203", "1544"], "lk-test");
    const hashHex = Buffer.from(hash.bytes).toString("hex");

    let current: LinkRequest | null = LinkRequest.create({
      id: LinkId.from("lk-test"),
      hash,
      clientId: "alice",
      createdAt: NOW,
      ttlMs: 60_000,
    });

    let casUsed = false;

    const store: LinkRequestStore = {
      async save(r: LinkRequest) { current = r; },
      async findByClientId() { return current; },
      async findByHash() { return current; },
      async deleteByClientId() { current = null; },
      async compareAndSave(
        _clientId: string,
        expectedStatus: string,
        request: LinkRequest,
      ) {
        casUsed = true;
        if (current && current.status === expectedStatus) {
          current = request;
          return true;
        }
        return false;
      },
    };

    const useCase = new VerifyDeviceLinkUseCase({
      linkRequestStore: store,
      nowMs: () => NOW + 5_000,
    });

    const result = await useCase.execute({ clientId: "alice", hashHex });

    expect(result.status).toBe("success");
    expect(casUsed).toBe(true);
  });
});
