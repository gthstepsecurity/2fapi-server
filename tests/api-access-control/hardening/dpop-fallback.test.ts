// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect, beforeEach } from "vitest";
import {
  ChannelBindingMethod,
  type ChannelBindingMethodType,
} from "../../../src/api-access-control/domain/model/channel-binding-method.js";
import { DpopProof } from "../../../src/api-access-control/domain/model/dpop-proof.js";
import type { DpopVerifier } from "../../../src/api-access-control/domain/port/outgoing/dpop-verifier.js";

// --- ChannelBindingMethod value object ---

describe("ChannelBindingMethod", () => {
  it("creates a tls-exporter method", () => {
    const method = ChannelBindingMethod.tlsExporter();
    expect(method.type).toBe("tls-exporter");
  });

  it("creates a dpop method", () => {
    const method = ChannelBindingMethod.dpop();
    expect(method.type).toBe("dpop");
  });

  it("auto-detects tls-exporter when both are available", () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: true,
      dpopProofPresent: true,
    });
    expect(method.type).toBe("tls-exporter");
  });

  it("falls back to dpop when tls-exporter is unavailable", () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: false,
      dpopProofPresent: true,
    });
    expect(method.type).toBe("dpop");
  });

  it("returns null when neither binding is available", () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: false,
      dpopProofPresent: false,
    });
    expect(method).toBeNull();
  });
});

// --- DpopProof value object ---

describe("DpopProof", () => {
  const validInput = {
    jti: "jti-unique-001",
    iat: Math.floor(Date.now() / 1000),
    thumbprint: "sha256-thumbprint-abc123",
    httpMethod: "POST",
    httpUri: "/api/verify",
  };

  it("creates a valid DPoP proof", () => {
    const proof = DpopProof.create(validInput);
    expect(proof.jti).toBe("jti-unique-001");
    expect(proof.thumbprint).toBe("sha256-thumbprint-abc123");
  });

  it("rejects DPoP proof with empty jti", () => {
    expect(() => DpopProof.create({ ...validInput, jti: "" })).toThrow("jti must not be empty");
  });

  it("rejects DPoP proof with empty thumbprint", () => {
    expect(() => DpopProof.create({ ...validInput, thumbprint: "" })).toThrow(
      "thumbprint must not be empty",
    );
  });

  it("detects expired iat (>60s in the past)", () => {
    const oldIat = Math.floor(Date.now() / 1000) - 120; // 2 minutes ago
    const proof = DpopProof.create({ ...validInput, iat: oldIat });
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(proof.isExpiredAt(nowSeconds, 60)).toBe(true);
  });

  it("is NOT expired at exactly maxAgeSec (boundary: > not >=)", () => {
    // Kill mutant: `nowSeconds - this.iat >= maxAgeSec` instead of `> maxAgeSec`
    const iat = 1000;
    const proof = DpopProof.create({ ...validInput, iat });
    // nowSeconds - iat = exactly 60 = maxAgeSec, should NOT be expired (> not >=)
    expect(proof.isExpiredAt(1060, 60)).toBe(false);
    // nowSeconds - iat = 61 > maxAgeSec, should be expired
    expect(proof.isExpiredAt(1061, 60)).toBe(true);
  });

  it("accepts iat within clock skew tolerance", () => {
    const recentIat = Math.floor(Date.now() / 1000) - 30; // 30s ago
    const proof = DpopProof.create({ ...validInput, iat: recentIat });
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(proof.isExpiredAt(nowSeconds, 60)).toBe(false);
  });
});

// --- DPoP verification integration tests ---

describe("DPoP verification flow", () => {
  /**
   * In-memory stub for DpopVerifier port.
   */
  class StubDpopVerifier implements DpopVerifier {
    private readonly usedJtis = new Set<string>();
    private validThumbprints = new Set<string>();

    setValidThumbprints(thumbprints: string[]): void {
      this.validThumbprints = new Set(thumbprints);
    }

    async verify(
      proof: DpopProof,
      nowSeconds: number,
      maxAgeSec: number,
    ): Promise<{ valid: boolean; error?: string }> {
      // Check expiry
      if (proof.isExpiredAt(nowSeconds, maxAgeSec)) {
        return { valid: false, error: "dpop_proof_expired" };
      }

      // Check jti replay
      if (this.usedJtis.has(proof.jti)) {
        return { valid: false, error: "dpop_jti_reused" };
      }
      this.usedJtis.add(proof.jti);

      return { valid: true };
    }

    async verifyThumbprintMatch(
      proof: DpopProof,
      expectedThumbprint: string,
    ): Promise<{ valid: boolean; error?: string }> {
      if (proof.thumbprint !== expectedThumbprint) {
        return { valid: false, error: "dpop_thumbprint_mismatch" };
      }
      return { valid: true };
    }
  }

  let verifier: StubDpopVerifier;

  beforeEach(() => {
    verifier = new StubDpopVerifier();
    verifier.setValidThumbprints(["thumb_alice_key"]);
  });

  it("accepts a valid DPoP proof when TLS exporter is unavailable", async () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: false,
      dpopProofPresent: true,
    });
    expect(method!.type).toBe("dpop");

    const proof = DpopProof.create({
      jti: "jti-001",
      iat: Math.floor(Date.now() / 1000),
      thumbprint: "thumb_alice_key",
      httpMethod: "POST",
      httpUri: "/api/verify",
    });

    const result = await verifier.verify(proof, Math.floor(Date.now() / 1000), 60);
    expect(result.valid).toBe(true);
  });

  it("rejects DPoP jti replay", async () => {
    const proof = DpopProof.create({
      jti: "jti-unique-replay",
      iat: Math.floor(Date.now() / 1000),
      thumbprint: "thumb_alice_key",
      httpMethod: "POST",
      httpUri: "/api/verify",
    });

    const nowSec = Math.floor(Date.now() / 1000);
    const first = await verifier.verify(proof, nowSec, 60);
    expect(first.valid).toBe(true);

    // Replay the same jti
    const second = await verifier.verify(proof, nowSec, 60);
    expect(second.valid).toBe(false);
    expect(second.error).toBe("dpop_jti_reused");
  });

  it("rejects DPoP proof with iat too old (>60s)", async () => {
    const proof = DpopProof.create({
      jti: "jti-old",
      iat: Math.floor(Date.now() / 1000) - 120,
      thumbprint: "thumb_alice_key",
      httpMethod: "POST",
      httpUri: "/api/verify",
    });

    const result = await verifier.verify(proof, Math.floor(Date.now() / 1000), 60);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("dpop_proof_expired");
  });

  it("rejects DPoP proof with thumbprint mismatch", async () => {
    const proof = DpopProof.create({
      jti: "jti-mismatch",
      iat: Math.floor(Date.now() / 1000),
      thumbprint: "thumb_eve_key",
      httpMethod: "POST",
      httpUri: "/api/verify",
    });

    const result = await verifier.verifyThumbprintMatch(proof, "thumb_alice_key");
    expect(result.valid).toBe(false);
    expect(result.error).toBe("dpop_thumbprint_mismatch");
  });

  it("rejects when no binding is available (neither TLS nor DPoP)", () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: false,
      dpopProofPresent: false,
    });
    expect(method).toBeNull();
    // Null method means "channel_binding_required" error
  });

  it("prefers TLS exporter over DPoP when both are available", () => {
    const method = ChannelBindingMethod.autoDetect({
      tlsExporterAvailable: true,
      dpopProofPresent: true,
    });
    expect(method!.type).toBe("tls-exporter");
  });

  it("accepts thumbprint match", async () => {
    const proof = DpopProof.create({
      jti: "jti-match",
      iat: Math.floor(Date.now() / 1000),
      thumbprint: "thumb_alice_key",
      httpMethod: "POST",
      httpUri: "/api/verify",
    });

    const result = await verifier.verifyThumbprintMatch(proof, "thumb_alice_key");
    expect(result.valid).toBe(true);
  });
});
