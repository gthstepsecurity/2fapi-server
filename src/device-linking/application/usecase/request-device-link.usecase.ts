// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  RequestDeviceLink,
  RequestDeviceLinkInput,
  RequestDeviceLinkOutput,
} from "../../domain/port/incoming/request-device-link.js";
import type { LinkRequestStore } from "../../domain/port/outgoing/link-request-store.js";
import { LinkId } from "../../domain/model/link-id.js";
import { LinkHash } from "../../domain/model/link-hash.js";
import { LinkRequest } from "../../domain/model/link-request.js";

const DEFAULT_LINK_TTL_MS = 60_000;
// 6 words = 2048⁶ = 73.8 quadrillion combinations.
// Nation-state with 10,000 GPUs: ~85 days to brute-force (vs 1.76s for 4 words).
// Admin can override via indexCount config (minimum 4, recommended 6-8).
const DEFAULT_INDEX_COUNT = 6;
const MAX_INDEX_GENERATION_ATTEMPTS = 1_000;

interface Dependencies {
  readonly linkRequestStore: LinkRequestStore;
  readonly randomHex: () => string;
  readonly randomIndex: () => number;
  readonly nowMs: () => number;
  readonly validateSession: (sessionId: string) => Promise<boolean>;
  readonly linkTtlMs?: number;
  readonly indexCount?: number;
  readonly maxAttempts?: number;
  readonly confirmationTtlMs?: number;
}

export class RequestDeviceLinkUseCase implements RequestDeviceLink {
  constructor(private readonly deps: Dependencies) {}

  async execute(input: RequestDeviceLinkInput): Promise<RequestDeviceLinkOutput> {
    const sessionValid = await this.deps.validateSession(input.sessionId);
    if (!sessionValid) {
      throw new Error("UNAUTHENTICATED");
    }

    // Invalidate any existing link request for this client
    await this.deps.linkRequestStore.deleteByClientId(input.clientId);

    // Generate random UNIQUE BIP-39 indexes (count is server-configured)
    // VENOM-02: Duplicates collapse entropy (2048^4 → 2048^1 worst case)
    // FIX RT-DL-10: Guard against degenerate randomIndex (constant or low-entropy)
    // that would cause an infinite loop trying to find unique values.
    const indexCount = this.deps.indexCount ?? DEFAULT_INDEX_COUNT;
    const indexSet = new Set<number>();
    let attempts = 0;
    while (indexSet.size < indexCount) {
      if (++attempts > MAX_INDEX_GENERATION_ATTEMPTS) {
        throw new Error(
          "ENTROPY_FAILURE: randomIndex produced too many duplicates. " +
          "Verify that randomIndex uses crypto.getRandomValues(), not Math.random().",
        );
      }
      indexSet.add(this.deps.randomIndex());
    }
    const indexes = Array.from(indexSet);

    // Generate linkId first — used as salt for the hash (SHADOW-01)
    const id = LinkId.generate(this.deps.randomHex);

    // Compute chained hash salted with linkId (prevents rainbow tables)
    // VENOM-01: Zero-pad to 4 chars — prevents cache-line oracle on word length
    const words = indexes.map((idx) => String(idx).padStart(4, "0"));
    const hash = LinkHash.fromWords(words, id.value);

    // Zero the words array (SHADOW-03: memory forensics defense)
    words.fill("");
    const request = LinkRequest.create({
      id,
      hash,
      clientId: input.clientId,
      createdAt: this.deps.nowMs(),
      ttlMs: this.deps.linkTtlMs ?? DEFAULT_LINK_TTL_MS,
      maxAttempts: this.deps.maxAttempts,
      confirmationTtlMs: this.deps.confirmationTtlMs,
    });

    await this.deps.linkRequestStore.save(request);

    // Return a frozen copy, then zero the working array (SHADOW-02)
    const result: RequestDeviceLinkOutput = {
      linkId: id.value,
      indexes: Object.freeze([...indexes]),
    };
    indexes.fill(0);

    return result;
  }
}
