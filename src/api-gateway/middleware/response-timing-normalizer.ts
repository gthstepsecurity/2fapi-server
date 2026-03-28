// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";

/**
 * FIX RT-DL-05 / RT-DL-08: normalize response timing for all endpoints.
 *
 * Without normalization, an observer measures:
 *   not_found  → ~2ms (1 DB read)
 *   hash_match → ~8ms (DB + timingSafeEqual + CAS)
 *   revokeAll  → ~5ms per device (N × DB write)
 *
 * This leaks: active clientIds, device count, authentication outcome.
 *
 * The normalizer pads EVERY response to a uniform time window:
 *   target ± random jitter (CSPRNG, not Math.random).
 *
 * Applied as an onSend hook — runs AFTER the route handler has written
 * the response body but BEFORE Fastify flushes to the socket.
 */

const DEFAULT_TARGET_MS = 50;
const DEFAULT_JITTER_MS = 10;

export interface TimingNormalizerOptions {
  /** Target response time in ms. Default: 50. */
  readonly targetMs?: number;
  /** Random jitter range in ms. Default: 10. */
  readonly jitterMs?: number;
  /** Route prefixes to normalize. Default: all /v1/ routes. */
  readonly prefixes?: string[];
}

export function registerResponseTimingNormalizer(
  app: FastifyInstance,
  options?: TimingNormalizerOptions,
): void {
  const targetMs = options?.targetMs ?? DEFAULT_TARGET_MS;
  const jitterMs = options?.jitterMs ?? DEFAULT_JITTER_MS;
  const prefixes = options?.prefixes ?? ["/v1/"];

  app.addHook("onRequest", async (request) => {
    // Record the start time on the request object
    (request as Record<string, unknown>).__timingStart = process.hrtime.bigint();
  });

  app.addHook("onSend", async (request, _reply, payload) => {
    const url = request.url;
    const shouldNormalize = prefixes.some((p) => url.startsWith(p));
    if (!shouldNormalize) return payload;

    const startNs = (request as Record<string, unknown>).__timingStart as
      | bigint
      | undefined;
    if (startNs === undefined) return payload;

    const elapsedNs = process.hrtime.bigint() - startNs;
    const elapsedMs = Number(elapsedNs) / 1_000_000;

    // CSPRNG jitter (not Math.random — see FIX C-01)
    const jitterBuf = randomBytes(4);
    const jitterFloat =
      ((jitterBuf[0]! << 24) | (jitterBuf[1]! << 16) | (jitterBuf[2]! << 8) | jitterBuf[3]!) >>> 0;
    const jitter = (jitterFloat / 0x1_0000_0000) * jitterMs;

    const effectiveTarget = targetMs + jitter;
    const delayMs = effectiveTarget - elapsedMs;

    if (delayMs > 0) {
      await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
    }

    return payload;
  });
}
