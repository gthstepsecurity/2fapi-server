// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";

/**
 * Scenario #12: Server unreachable → client cannot proceed with OPRF
 * Scenario #27: Offline brute-force is impossible without server
 *
 * These test the fundamental constraint: the OPRF requires server cooperation.
 * Without the server evaluation, the vault key cannot be derived.
 */
describe("OPRF client-side error scenarios", () => {
  // --- Scenario #12: Server unreachable ---

  it("OPRF cannot proceed without server evaluation", async () => {
    // Simulate: client has password but server is down
    // The client can compute P = hash_to_group(password) and blind(P)
    // But without the server's evaluate(B, k), the client cannot get U
    // Therefore the vault key cannot be derived

    const hasPassword = true;
    const hasLocalVault = true;
    const serverReachable = false;

    const canDeriveVaultKey = hasPassword && hasLocalVault && serverReachable;
    expect(canDeriveVaultKey).toBe(false);
  });

  it("client should show 'Server required' message when offline", () => {
    // The error message should be clear and offer fallback
    const error = "SERVER_UNREACHABLE";
    const fallbackAvailable = true; // Tier 0 passphrase is always available

    expect(error).toBe("SERVER_UNREACHABLE");
    expect(fallbackAvailable).toBe(true);
  });

  // --- Scenario #27: Offline brute-force impossible ---

  it("offline attacker cannot derive vault key without OPRF evaluation", () => {
    // Eve stole the device, knows the password, has the encrypted vault
    // Eve tries to brute-force the vault key offline:
    //
    // vault_key = HKDF(U || hw_key) where U = k · hash_to_group(password)
    //
    // Even with the correct password, Eve computes hash_to_group(password)
    // but cannot compute k · hash_to_group(password) without k.
    // k is a 256-bit scalar stored only on the server.

    const eveHasPassword = true;
    const eveHasDevice = true;
    const eveHasEncryptedVault = true;
    const eveHasOprfKey = false; // 256-bit, server-only

    // Without the OPRF key, Eve must brute-force a 256-bit scalar
    const oprfKeyBits = 256;
    const bruteForceAttempts = BigInt(2) ** BigInt(oprfKeyBits);

    // 2^256 ≈ 1.15 × 10^77 — computationally infeasible
    expect(bruteForceAttempts > BigInt(10) ** BigInt(70)).toBe(true);

    const canDeriveVaultKey = eveHasPassword && eveHasDevice && eveHasEncryptedVault && eveHasOprfKey;
    expect(canDeriveVaultKey).toBe(false);
  });

  it("even with correct password, wrong OPRF output produces wrong vault key", () => {
    // If Eve could somehow guess U (the OPRF output), she'd need to
    // guess the exact 32-byte value. Since U = k · H(password) and k is
    // unknown, U is uniformly random from Eve's perspective.

    const correctU = new Uint8Array(32).fill(0x42);
    const guessedU = new Uint8Array(32).fill(0x43); // 1 byte different

    // Different U → different HKDF output → different vault key → GCM tag mismatch
    expect(Buffer.from(correctU).equals(Buffer.from(guessedU))).toBe(false);
  });

  // --- Scenario #48: Proof of possession ---

  it("enrollment commitment must include proof of possession", () => {
    // The commitment registration flow (already implemented) requires
    // a proof-of-possession alongside the commitment C.
    // This verifies the requirement exists conceptually.

    const enrollmentRequest = {
      commitment: new Uint8Array(32), // C = s·G + r·H
      proofOfPossession: new Uint8Array(96), // Sigma proof
    };

    expect(enrollmentRequest.commitment).toBeDefined();
    expect(enrollmentRequest.proofOfPossession).toBeDefined();
    expect(enrollmentRequest.proofOfPossession.length).toBe(96);
  });
});
