// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { InputHardeningPolicy } from "../../../src/zk-verification/domain/service/input-hardening-policy.js";

describe("InputHardeningPolicy", () => {
  const policy = new InputHardeningPolicy();

  // --- Payload size ---

  it("should accept payload of exactly 96 bytes", () => {
    const payload = new Uint8Array(96);
    payload[0] = 0x01; // non-identity
    const result = policy.validate(payload);
    expect(result).toBeNull();
  });

  it("should reject payload exceeding 1024 bytes", () => {
    const payload = new Uint8Array(1025);
    payload[0] = 0x01;
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.code).toBe("PAYLOAD_TOO_LARGE");
  });

  it("should accept payload of exactly 1024 bytes", () => {
    const payload = new Uint8Array(1024);
    payload[0] = 0x01;
    const result = policy.validate(payload);
    // Payload is within size limit, but not 96 bytes, so it should fail
    // on proof length rather than size. Let's test size with >1024.
    // Actually, the hardening policy checks size first, then defers to
    // proof parsing. A 1024-byte payload is within the size limit.
    expect(result).toBeNull();
  });

  // --- All-zeros proof (identity point) ---

  it("should reject all-zeros payload (identity point announcement)", () => {
    const payload = new Uint8Array(96); // all zeros
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.code).toBe("IDENTITY_PROOF");
  });

  // --- All-0xFF proof (non-canonical) ---

  it("should reject all-0xFF payload (non-canonical encoding)", () => {
    const payload = new Uint8Array(96).fill(0xff);
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.code).toBe("NON_CANONICAL_PROOF");
  });

  // --- Oversized fields within valid-length proof ---

  it("should reject proof where all three fields are 0xFF (non-canonical)", () => {
    const payload = new Uint8Array(96).fill(0xff);
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
  });

  // --- Valid proof passes ---

  it("should accept a well-formed proof payload", () => {
    const payload = new Uint8Array(96);
    payload[0] = 0x01; // non-identity announcement
    payload[32] = 0x02; // responseS
    payload[64] = 0x03; // responseR
    const result = policy.validate(payload);
    expect(result).toBeNull();
  });

  // --- Empty payload ---

  it("should accept empty payload within size limit (not the policy's job to check proof length)", () => {
    // InputHardeningPolicy only checks: size > 1024, identity proof, all-0xFF
    // It does NOT check that payload is exactly 96 bytes (that's the existing policy's job)
    const payload = new Uint8Array(0);
    // Empty is within 1024 limit. It's not all-zeros of 96 bytes. Not all-0xFF of 96 bytes.
    const result = policy.validate(payload);
    expect(result).toBeNull();
  });

  it("should include descriptive message for payload too large", () => {
    // Kill mutant: message replaced by ""
    const payload = new Uint8Array(1025);
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.message).toContain("1024");
    expect(result!.message.length).toBeGreaterThan(0);
  });

  it("should include descriptive message for identity proof", () => {
    // Kill mutant: message replaced by ""
    const payload = new Uint8Array(96); // all zeros
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.message).toContain("zero bytes");
    expect(result!.message.length).toBeGreaterThan(0);
  });

  it("should include descriptive message for non-canonical proof", () => {
    // Kill mutant: message replaced by ""
    const payload = new Uint8Array(96).fill(0xff);
    const result = policy.validate(payload);
    expect(result).not.toBeNull();
    expect(result!.message).toContain("0xFF");
    expect(result!.message.length).toBeGreaterThan(0);
  });

  it("should use < (not <=) in isAllZeros/isAllOnes loop", () => {
    // Kill mutant: `for (let i = 0; i <= bytes.length; i++)` — off-by-one
    // With <=, accessing bytes[bytes.length] returns undefined, which could break the logic
    const payload = new Uint8Array(96);
    payload[0] = 0x01; // non-zero byte
    const result = policy.validate(payload);
    expect(result).toBeNull();
  });
});
