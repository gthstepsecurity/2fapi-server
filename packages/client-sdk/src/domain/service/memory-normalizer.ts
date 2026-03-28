// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Domain service: normalizes WASM memory footprint across all tiers.
 *
 * R19-04: All tiers must produce the same 64MB allocation.
 * R21-01: The PAGE FAULT PATTERN must be identical (not just the size).
 *         Sequential fill + random mixing (Argon2id signature) vs
 *         sequential fill only (dummy) is distinguishable.
 * R21-02: The 64MB must be PRE-ALLOCATED at tab load, not at auth time,
 *         to hide the authentication moment.
 *
 * Solution:
 * - Pre-allocate 64MB at SDK initialization (no spike at auth time)
 * - For Tier 1/2: run REAL Argon2id on a dummy passphrase (identical
 *   page fault pattern to Tier 0 — random mixing phase included)
 * - Discard the dummy Argon2id output (it's meaningless)
 */

const TARGET_ALLOCATION_BYTES = 64 * 1024 * 1024;

export class MemoryNormalizer {
  private preAllocated: Uint8Array | null = null;

  constructor(
    private readonly allocator: (size: number) => Uint8Array,
    private readonly randomFill: (buffer: Uint8Array) => void,
    private readonly dummyArgon2id?: () => Promise<void>,
  ) {}

  /**
   * Pre-allocate WASM memory at SDK initialization.
   * The 64MB is resident from tab load to tab close — no spike at auth time.
   * Call this ONCE at SDK init, not per authentication.
   */
  preAllocate(): void {
    if (this.preAllocated) return;
    this.preAllocated = this.allocator(TARGET_ALLOCATION_BYTES);
    this.randomFill(this.preAllocated); // touch every page to make resident
    // Zeroize after touching — pages are now physically mapped but contain zeros
    this.preAllocated.fill(0);
  }

  /**
   * After authentication, ensure the page fault pattern matches Argon2id.
   *
   * R21-01 FIX: Instead of just filling memory with random data (sequential
   * write pattern), run ACTUAL Argon2id on a dummy passphrase. This produces
   * the EXACT same page fault signature: sequential fill + random mixing.
   *
   * @param argon2idAlreadyRan - true if Tier 0 already ran real Argon2id
   */
  async normalizeAccessPattern(argon2idAlreadyRan: boolean): Promise<void> {
    if (argon2idAlreadyRan) return; // Tier 0: real Argon2id already produced the pattern

    // Tier 1/2: run Argon2id on dummy input to produce identical page fault pattern
    if (this.dummyArgon2id) {
      await this.dummyArgon2id();
      // The dummy Argon2id output is discarded by the callback.
      // The WASM memory used by Argon2id is zeroized by the Rust zeroize crate
      // (DerivedCredential derives ZeroizeOnDrop).
    } else {
      // Fallback: sequential fill + zeroize
      const dummy = this.allocator(TARGET_ALLOCATION_BYTES);
      this.randomFill(dummy);
      dummy.fill(0); // zeroize immediately
    }
  }

  /**
   * Check if memory was pre-allocated.
   */
  get isPreAllocated(): boolean {
    return this.preAllocated !== null;
  }
}
