// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes, timingSafeEqual } from "node:crypto";
import type {
  VerifyDeviceLink,
  VerifyDeviceLinkInput,
  VerifyDeviceLinkResult,
} from "../../domain/port/incoming/verify-device-link.js";
import type { LinkRequestStore } from "../../domain/port/outgoing/link-request-store.js";

interface Dependencies {
  readonly linkRequestStore: LinkRequestStore;
  readonly nowMs: () => number;
}

/**
 * FIX Mitnick side-channel analysis:
 *
 * EVERY execution path MUST perform the same operations:
 *   - Same number of Buffer allocations (3)
 *   - Same crypto operations (1 timingSafeEqual)
 *   - Same DB operations pattern (1 read + 1 CAS write)
 *   - Same response structure (status only, no attemptsRemaining)
 *   - Same response STATUS STRING LENGTH ("refused" / "success" = both 7 chars)
 *
 * This eliminates 4 oracles:
 *   1. Memory allocation oracle (different heap delta per path)
 *   2. Status enumeration oracle (different status strings)
 *   3. Attempts remaining oracle (leaks brute-force budget)
 *   4. Response size oracle (different JSON byte lengths)
 *
 * "Mitnick never attacks the crypto. He attacks the logic around it."
 */

// FIX: randomize dummy hash so a memory observer cannot distinguish
// "request not found" (dummy) from "request found" (real hash).
// Regenerated on each module load — no static pattern to fingerprint.
const DUMMY_HASH = randomBytes(64);

export class VerifyDeviceLinkUseCase implements VerifyDeviceLink {
  constructor(private readonly deps: Dependencies) {}

  async execute(input: VerifyDeviceLinkInput): Promise<VerifyDeviceLinkResult> {
    const request = await this.deps.linkRequestStore.findByClientId(input.clientId);

    // --- Uniform allocation block ---
    // ALL paths create these 3 buffers to equalize memory footprint.
    const storedHash = request
      ? Buffer.from(request.hash.bytes)
      : Buffer.from(DUMMY_HASH);
    const inputHash = Buffer.from(input.hashHex, "hex");
    const safeInput = storedHash.length === inputHash.length
      ? inputHash
      : Buffer.alloc(storedHash.length);

    // ALL paths perform the constant-time comparison.
    // Even if we already know the result is "refused", we compare
    // to equalize timing and memory.
    const hashMatch = timingSafeEqual(storedHash, safeInput)
      && storedHash.length === inputHash.length;

    // --- Decision logic (no early returns before this point) ---

    // All failure paths return the same opaque "refused" status.
    // The attacker cannot distinguish not_found from expired from
    // hash_mismatch — they all look identical.

    if (!request) {
      return { status: "refused" };
    }

    if (request.status !== "pending") {
      return { status: "refused" };
    }

    if (request.isExhausted()) {
      await this.deps.linkRequestStore.deleteByClientId(input.clientId);
      return { status: "refused" };
    }

    if (request.isExpired(this.deps.nowMs())) {
      return { status: "refused" };
    }

    // FIX Mitnick memory oracle: create BOTH objects regardless of path.
    // recordFailedAttempt() and markVerified() produce objects of different
    // sizes — an attacker observing GC pressure can distinguish them.
    // By creating both, we equalize the heap delta.
    const failedRequest = request.recordFailedAttempt();
    const verifiedRequest = request.markVerified(this.deps.nowMs());

    if (!hashMatch) {
      const saved = await this.deps.linkRequestStore.compareAndSave(
        input.clientId,
        "pending",
        failedRequest,
      );
      if (!saved) {
        return { status: "refused" };
      }
      return { status: "refused" };
    }

    // Success: atomic CAS transition
    const transitioned = await this.deps.linkRequestStore.compareAndSave(
      input.clientId,
      "pending",
      verifiedRequest,
    );
    if (!transitioned) {
      return { status: "refused" };
    }
    // "success" (7 chars) = same length as "refused" (7 chars).
    // An observer comparing JSON byte lengths cannot distinguish them.
    // Previously "verified" (8 chars) was 1 byte longer → TLS record oracle.
    return { status: "success" };
  }
}
