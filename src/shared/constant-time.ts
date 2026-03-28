// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Constant-time comparison utility.
 *
 * Delegates to Rust napi (subtle::ConstantTimeEq) when available.
 * Falls back to a TypeScript XOR accumulator implementation when the
 * native module is not loaded. The fallback is NOT guaranteed
 * constant-time due to JIT optimization, but provides defense-in-depth.
 *
 * Production deployments SHOULD use the native module.
 */

interface NativeConstantTimeModule {
  constantTimeEq(a: Buffer, b: Buffer): boolean;
}

let nativeModule: NativeConstantTimeModule | null = null;
let warnOnFallback = false;
let fallbackWarningEmitted = false;

/**
 * Injects the native constant-time comparison module.
 * Called during application bootstrap when the napi module is available.
 */
export function setNativeConstantTimeModule(mod: NativeConstantTimeModule): void {
  nativeModule = mod;
}

/**
 * Resets the native module (for testing purposes only).
 */
export function resetNativeConstantTimeModule(): void {
  nativeModule = null;
  fallbackWarningEmitted = false;
}

/**
 * Returns true if the native constant-time module is loaded.
 * Production startup can check this to ensure the native module is available.
 */
export function isNativeAvailable(): boolean {
  return nativeModule !== null;
}

/**
 * Enables or disables a warning when the TypeScript fallback is used.
 * When enabled, a single warning is emitted to stderr the first time
 * the fallback is used. Subsequent calls do not re-emit the warning.
 */
export function setWarnOnFallback(enabled: boolean): void {
  warnOnFallback = enabled;
  if (!enabled) {
    fallbackWarningEmitted = false;
  }
}

/**
 * Throws if the native constant-time module is not loaded.
 * Call at server startup in production to ensure the native module is available.
 * Without the native module, constant-time comparisons fall back to a TypeScript
 * XOR accumulator that is NOT guaranteed constant-time due to JIT optimization.
 */
export function requireNative(): void {
  if (nativeModule === null) {
    throw new Error(
      "Native constant-time module is required but not loaded. " +
      "Ensure @2fapi/crypto-native is installed and setNativeConstantTimeModule() is called at startup.",
    );
  }
}

/**
 * Constant-time equality comparison for byte arrays.
 *
 * When the native Rust module is available, delegates to
 * subtle::ConstantTimeEq via napi. Otherwise falls back to a
 * TypeScript XOR accumulator.
 *
 * @returns true if both arrays contain identical bytes
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (nativeModule !== null) {
    return nativeModule.constantTimeEq(Buffer.from(a), Buffer.from(b));
  }
  if (warnOnFallback && !fallbackWarningEmitted) {
    fallbackWarningEmitted = true;
    process.stderr.write(
      "[2fapi] WARNING: using TypeScript fallback for constant-time comparison. Load the native Rust module for production security.\n",
    );
  }
  return xorAccumulatorEqual(a, b);
}

/**
 * TypeScript fallback: XOR accumulator comparison.
 *
 * WARNING: Not guaranteed constant-time due to V8/JIT optimizations.
 * Use the native Rust module in production.
 */
function xorAccumulatorEqual(a: Uint8Array, b: Uint8Array): boolean {
  const maxLen = Math.max(a.length, b.length);
  let acc = a.length ^ b.length; // non-zero if lengths differ
  for (let i = 0; i < maxLen; i++) {
    acc |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return acc === 0;
}
