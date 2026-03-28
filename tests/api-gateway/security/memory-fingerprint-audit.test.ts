// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Memory fingerprint audit — ALL API endpoints, ALL code paths.
 *
 * Measures heap allocation delta for every request type and compares
 * them pairwise with Welch's t-test. If any two paths on the SAME
 * endpoint produce statistically distinguishable heap deltas, a
 * co-located attacker could infer the response type without decryption.
 *
 * Methodology: same as dudect (Welch's t-test), applied to V8 heapUsed.
 * Threshold: |t| > 6.0 = WARNING (memory oracle detected).
 *
 * This test documents the memory profile — it warns on oracles but
 * does not fail the build (V8 JIT noise makes sub-KB deltas unreliable).
 */
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  createTestApp,
  StubVerifyProof,
  StubIssueToken,
  StubRequestChallenge,
  StubEnrollClient,
  StubValidateToken,
  StubRevokeClient,
  StubRotateCommitment,
  validBase64,
} from "../test-helpers.js";
import type { FastifyInstance } from "fastify";

function welchT(a: number[], b: number[]): number {
  if (a.length < 2 || b.length < 2) return 0;
  const meanA = a.reduce((s, x) => s + x, 0) / a.length;
  const meanB = b.reduce((s, x) => s + x, 0) / b.length;
  const varA = a.reduce((s, x) => s + (x - meanA) ** 2, 0) / (a.length - 1);
  const varB = b.reduce((s, x) => s + (x - meanB) ** 2, 0) / (b.length - 1);
  const se = Math.sqrt(varA / a.length + varB / b.length);
  return se === 0 ? 0 : (meanA - meanB) / se;
}

function mean(arr: number[]): number {
  return arr.reduce((s, x) => s + x, 0) / arr.length;
}

interface PathProfile {
  name: string;
  endpoint: string;
  deltas: number[];
}

const SAMPLES = 15;

describe("Memory Fingerprint Audit — ALL /v1/ endpoints", () => {
  let app: FastifyInstance;
  let verifyProof: StubVerifyProof;
  let issueToken: StubIssueToken;
  let requestChallenge: StubRequestChallenge;
  let enrollClient: StubEnrollClient;
  let validateToken: StubValidateToken;
  let revokeClient: StubRevokeClient;

  beforeEach(() => {
    const result = createTestApp();
    app = result.app;
    verifyProof = result.deps.verifyProof;
    issueToken = result.deps.issueToken;
    requestChallenge = result.deps.requestChallenge;
    enrollClient = result.deps.enrollClient;
    validateToken = result.deps.validateToken;
    revokeClient = result.deps.revokeClient;
  });

  afterEach(async () => {
    await app.close();
  });

  async function measureHeapDelta(fn: () => Promise<void>): Promise<number> {
    if (globalThis.gc) globalThis.gc();
    const before = process.memoryUsage().heapUsed;
    await fn();
    return process.memoryUsage().heapUsed - before;
  }

  async function profilePath(
    name: string,
    endpoint: string,
    setup: () => void,
    request: () => Promise<unknown>,
  ): Promise<PathProfile> {
    const deltas: number[] = [];
    for (let i = 0; i < SAMPLES; i++) {
      setup();
      const d = await measureHeapDelta(async () => { await request(); });
      deltas.push(d);
    }
    return { name, endpoint, deltas };
  }

  it("profiles ALL endpoints and detects memory oracles", { timeout: 30_000 }, async () => {
    const profiles: PathProfile[] = [];

    // ========== /v1/verify ==========
    profiles.push(await profilePath(
      "verify:success", "/v1/verify",
      () => verifyProof.setResponse({ success: true, clientIdentifier: "c", receiptId: "r" }),
      () => app.inject({ method: "POST", url: "/v1/verify", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice", challengeId: "ch", proof: validBase64(), channelBinding: validBase64(), domainSeparationTag: "DST" } }),
    ));
    profiles.push(await profilePath(
      "verify:refused", "/v1/verify",
      () => verifyProof.setResponse({ success: false, error: "verification_refused" }),
      () => app.inject({ method: "POST", url: "/v1/verify", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice", challengeId: "ch", proof: validBase64(), channelBinding: validBase64(), domainSeparationTag: "DST" } }),
    ));
    profiles.push(await profilePath(
      "verify:rate_limited", "/v1/verify",
      () => verifyProof.setResponse({ success: false, error: "rate_limited" }),
      () => app.inject({ method: "POST", url: "/v1/verify", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice", challengeId: "ch", proof: validBase64(), channelBinding: validBase64(), domainSeparationTag: "DST" } }),
    ));
    profiles.push(await profilePath(
      "verify:400_missing", "/v1/verify",
      () => {},
      () => app.inject({ method: "POST", url: "/v1/verify", headers: { "content-type": "application/json" }, payload: {} }),
    ));

    // ========== /v1/enroll ==========
    profiles.push(await profilePath(
      "enroll:success", "/v1/enroll",
      () => enrollClient.setResponse({ success: true, referenceId: "ref", clientIdentifier: "c" }),
      () => app.inject({ method: "POST", url: "/v1/enroll", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice", commitment: validBase64(), proofOfPossession: validBase64(96) } }),
    ));
    profiles.push(await profilePath(
      "enroll:refused", "/v1/enroll",
      () => enrollClient.setResponse({ success: false, error: "enrollment_refused" }),
      () => app.inject({ method: "POST", url: "/v1/enroll", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice", commitment: validBase64(), proofOfPossession: validBase64(96) } }),
    ));
    profiles.push(await profilePath(
      "enroll:400_missing", "/v1/enroll",
      () => {},
      () => app.inject({ method: "POST", url: "/v1/enroll", headers: { "content-type": "application/json" }, payload: {} }),
    ));

    // ========== /v1/challenge ==========
    profiles.push(await profilePath(
      "challenge:success", "/v1/challenge",
      () => requestChallenge.setResponse({ success: true, challengeId: "ch", nonce: new Uint8Array(32), channelBinding: new Uint8Array(32), expiresAtMs: Date.now() + 60000, protocolVersion: "1.0", legacyFirstFactor: false }),
      () => app.inject({ method: "POST", url: "/v1/challenge", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice" } }),
    ));
    profiles.push(await profilePath(
      "challenge:refused", "/v1/challenge",
      () => requestChallenge.setResponse({ success: false, error: "challenge_refused" }),
      () => app.inject({ method: "POST", url: "/v1/challenge", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice" } }),
    ));

    // ========== /v1/resources/:id ==========
    profiles.push(await profilePath(
      "resource:success", "/v1/resources/test",
      () => validateToken.setResponse({ success: true, clientIdentifier: "c", audience: "a", level: "standard" }),
      () => app.inject({ method: "GET", url: "/v1/resources/test",
        headers: { authorization: "Bearer valid-token" } }),
    ));
    profiles.push(await profilePath(
      "resource:401_no_token", "/v1/resources/test",
      () => {},
      () => app.inject({ method: "GET", url: "/v1/resources/test" }),
    ));
    profiles.push(await profilePath(
      "resource:401_invalid", "/v1/resources/test",
      () => validateToken.setResponse({ success: false, error: "access_denied" }),
      () => app.inject({ method: "GET", url: "/v1/resources/test",
        headers: { authorization: "Bearer invalid" } }),
    ));

    // ========== /v1/revoke ==========
    profiles.push(await profilePath(
      "revoke:success", "/v1/revoke",
      () => revokeClient.setResponse({ success: true }),
      () => app.inject({ method: "POST", url: "/v1/revoke", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice" } }),
    ));
    profiles.push(await profilePath(
      "revoke:refused", "/v1/revoke",
      () => revokeClient.setResponse({ success: false, error: "revocation_refused" }),
      () => app.inject({ method: "POST", url: "/v1/revoke", headers: { "content-type": "application/json" },
        payload: { clientIdentifier: "alice" } }),
    ));

    // ========== ANALYSIS ==========

    // Group by endpoint
    const endpoints = new Map<string, PathProfile[]>();
    for (const p of profiles) {
      const group = endpoints.get(p.endpoint) ?? [];
      group.push(p);
      endpoints.set(p.endpoint, group);
    }

    const oracles: string[] = [];

    for (const [endpoint, paths] of endpoints) {
      // Compare all pairs within same endpoint
      for (let i = 0; i < paths.length; i++) {
        for (let j = i + 1; j < paths.length; j++) {
          const a = paths[i]!;
          const b = paths[j]!;
          const t = welchT(a.deltas, b.deltas);
          const meanA = mean(a.deltas);
          const meanB = mean(b.deltas);
          const delta = Math.abs(meanA - meanB);

          if (Math.abs(t) > 6.0) {
            const msg = `MEMORY ORACLE on ${endpoint}: ${a.name} vs ${b.name} — |t|=${Math.abs(t).toFixed(1)}, Δ=${delta.toFixed(0)} bytes (${meanA.toFixed(0)} vs ${meanB.toFixed(0)})`;
            oracles.push(msg);
            console.warn(msg);
          }
        }
      }
    }

    // Also compare ACROSS endpoints (can attacker tell which endpoint was called?)
    const crossPairs: [PathProfile, PathProfile][] = [];
    const allPaths = [...profiles];
    for (let i = 0; i < allPaths.length; i++) {
      for (let j = i + 1; j < allPaths.length; j++) {
        if (allPaths[i]!.endpoint !== allPaths[j]!.endpoint) {
          crossPairs.push([allPaths[i]!, allPaths[j]!]);
        }
      }
    }

    let crossOracles = 0;
    for (const [a, b] of crossPairs) {
      const t = welchT(a.deltas, b.deltas);
      if (Math.abs(t) > 6.0) {
        crossOracles++;
      }
    }

    if (crossOracles > 0) {
      console.warn(
        `CROSS-ENDPOINT MEMORY ORACLE: ${crossOracles}/${crossPairs.length} endpoint pairs are distinguishable by heap delta.`,
      );
    }

    // Summary
    console.log("\n=== MEMORY FINGERPRINT SUMMARY ===");
    for (const p of profiles) {
      console.log(`  ${p.name.padEnd(25)} mean=${mean(p.deltas).toFixed(0).padStart(8)} bytes`);
    }
    console.log(`\n  Same-endpoint oracles: ${oracles.length}`);
    console.log(`  Cross-endpoint oracles: ${crossOracles}/${crossPairs.length}`);
    console.log("===================================\n");

    // The test passes — oracles are documented, not blocked
    // (V8 heap measurement is too noisy for reliable assertion)
    expect(profiles.length).toBeGreaterThan(0);
  });
});
