// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Empirical timing verification for the response timing normalizer.
 *
 * Same methodology as dudect (Welch's t-test on timing distributions),
 * applied to HTTP response times instead of CPU cycles.
 *
 * Threshold: |t| < 4.5 = PASS (no detectable timing difference)
 *            |t| > 4.5 = FAIL (observer can distinguish response types)
 *
 * This test verifies that the timing normalizer makes success (200)
 * and failure (401) responses statistically indistinguishable.
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubVerifyProof,
  StubIssueToken,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

/**
 * Welch's t-test for two independent samples.
 *
 * Returns the t-statistic. |t| < 4.5 means no statistically significant
 * difference between the two distributions (p < 0.00001 threshold).
 */
function welchTTest(a: number[], b: number[]): number {
  const meanA = a.reduce((s, x) => s + x, 0) / a.length;
  const meanB = b.reduce((s, x) => s + x, 0) / b.length;
  const varA = a.reduce((s, x) => s + (x - meanA) ** 2, 0) / (a.length - 1);
  const varB = b.reduce((s, x) => s + (x - meanB) ** 2, 0) / (b.length - 1);
  const se = Math.sqrt(varA / a.length + varB / b.length);
  if (se === 0) return 0;
  return (meanA - meanB) / se;
}

describe("Response Timing Normalizer — Empirical Verification (dudect-style)", () => {
  let app: FastifyInstance;
  let verifyProof: StubVerifyProof;
  let issueToken: StubIssueToken;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    verifyProof = result.deps.verifyProof;
    issueToken = result.deps.issueToken;
  });

  afterEach(async () => {
    await app.close();
  });

  function validPayload() {
    return {
      clientIdentifier: "alice-payment-service",
      challengeId: "ch-42",
      proof: validBase64(),
      channelBinding: validBase64(),
      domainSeparationTag: "2FApi-v1.0-Sigma",
    };
  }

  async function measureRequestMs(): Promise<number> {
    const start = process.hrtime.bigint();
    await app.inject({
      method: "POST",
      url: "/v1/verify",
      headers: { "content-type": "application/json" },
      payload: validPayload(),
    });
    const elapsed = process.hrtime.bigint() - start;
    return Number(elapsed) / 1_000_000; // ns → ms
  }

  it("success and failure response times are indistinguishable (Welch t-test)", { timeout: 15_000 }, async () => {
    const SAMPLES = 20;
    const successTimes: number[] = [];
    const failureTimes: number[] = [];

    // Warm up (JIT, caches)
    verifyProof.setResponse({ success: true, clientIdentifier: "test-client", receiptId: "r1" });
    await measureRequestMs();
    verifyProof.setResponse({ success: false, error: "verification_refused" });
    await measureRequestMs();

    // Interleaved sampling (reduces systematic bias)
    for (let i = 0; i < SAMPLES; i++) {
      // Success measurement
      verifyProof.setResponse({ success: true, clientIdentifier: "test-client", receiptId: "r1" });
      successTimes.push(await measureRequestMs());

      // Failure measurement
      verifyProof.setResponse({ success: false, error: "verification_refused" });
      failureTimes.push(await measureRequestMs());
    }

    const t = welchTTest(successTimes, failureTimes);

    // |t| < 4.5 = no detectable timing difference (same threshold as dudect)
    expect(
      Math.abs(t),
      `Timing oracle detected: |t| = ${Math.abs(t).toFixed(2)} (threshold: 4.5). ` +
      `Success mean: ${(successTimes.reduce((a, b) => a + b, 0) / SAMPLES).toFixed(2)}ms, ` +
      `Failure mean: ${(failureTimes.reduce((a, b) => a + b, 0) / SAMPLES).toFixed(2)}ms`,
    ).toBeLessThan(4.5);
  });

  it("rate_limited and verification_refused times are indistinguishable", { timeout: 15_000 }, async () => {
    const SAMPLES = 20;
    const rateLimitedTimes: number[] = [];
    const refusedTimes: number[] = [];

    for (let i = 0; i < SAMPLES; i++) {
      verifyProof.setResponse({ success: false, error: "rate_limited" });
      rateLimitedTimes.push(await measureRequestMs());

      verifyProof.setResponse({ success: false, error: "verification_refused" });
      refusedTimes.push(await measureRequestMs());
    }

    const t = welchTTest(rateLimitedTimes, refusedTimes);

    expect(
      Math.abs(t),
      `Timing oracle between rate_limited and verification_refused: |t| = ${Math.abs(t).toFixed(2)}`,
    ).toBeLessThan(4.5);
  });
});
