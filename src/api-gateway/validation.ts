// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Shared validation utilities for API gateway routes.
 */

const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

export function isValidBase64(value: string): boolean {
  if (value.length === 0) return false;
  return BASE64_REGEX.test(value);
}

export function decodeBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64"));
}

const CLIENT_ID_REGEX = /^[a-zA-Z0-9._-]+$/;

export function isValidClientIdentifier(value: string): boolean {
  if (value.length === 0 || value.length > 128) return false;
  return CLIENT_ID_REGEX.test(value);
}

/**
 * FIX L-01: restrict domain separation tags to ASCII printable subset.
 *
 * Previously only length was validated; Unicode payloads were accepted.
 * Allowing arbitrary Unicode is dangerous because:
 *   - Homoglyph attacks (Cyrillic "а" vs Latin "a") can produce
 *     visually identical but cryptographically different transcripts.
 *   - Bidirectional control chars can mislead log/audit viewers.
 *   - Normalization forms (NFC/NFD) may differ across platforms,
 *     leading to transcript mismatches.
 *
 * Allowed: [a-zA-Z0-9._\-] (matches protocol DSTs like "2FApi-v1.0-Sigma").
 */
const DST_REGEX = /^[a-zA-Z0-9._-]+$/;
const DST_MAX_LENGTH = 64;

export function isValidDomainSeparationTag(value: string): boolean {
  if (value.length === 0 || value.length > DST_MAX_LENGTH) return false;
  return DST_REGEX.test(value);
}

const SAFE_REDIS_KEY_REGEX = /[^a-zA-Z0-9._-]/g;

/**
 * Strips any characters outside [a-zA-Z0-9._-] to prevent Redis key injection.
 * Use on all user-supplied values before they enter Redis key construction.
 */
export function sanitizeRedisKey(key: string): string {
  return key.replace(SAFE_REDIS_KEY_REGEX, "");
}
