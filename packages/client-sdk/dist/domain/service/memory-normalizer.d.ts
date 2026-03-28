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
export declare class MemoryNormalizer {
    private readonly allocator;
    private readonly randomFill;
    private readonly dummyArgon2id?;
    private preAllocated;
    constructor(allocator: (size: number) => Uint8Array, randomFill: (buffer: Uint8Array) => void, dummyArgon2id?: (() => Promise<void>) | undefined);
    /**
     * Pre-allocate WASM memory at SDK initialization.
     * The 64MB is resident from tab load to tab close — no spike at auth time.
     * Call this ONCE at SDK init, not per authentication.
     */
    preAllocate(): void;
    /**
     * After authentication, ensure the page fault pattern matches Argon2id.
     *
     * R21-01 FIX: Instead of just filling memory with random data (sequential
     * write pattern), run ACTUAL Argon2id on a dummy passphrase. This produces
     * the EXACT same page fault signature: sequential fill + random mixing.
     *
     * @param argon2idAlreadyRan - true if Tier 0 already ran real Argon2id
     */
    normalizeAccessPattern(argon2idAlreadyRan: boolean): Promise<void>;
    /**
     * Check if memory was pre-allocated.
     */
    get isPreAllocated(): boolean;
}
//# sourceMappingURL=memory-normalizer.d.ts.map
