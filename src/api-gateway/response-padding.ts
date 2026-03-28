// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";

/**
 * FIX RT-36 / RT-DL-09: pad JSON responses to a uniform byte size.
 *
 * Without padding, TLS record sizes reveal response type:
 *   401 error → ~170 bytes
 *   200 token → ~250+ bytes
 * An observer distinguishes success/failure without decrypting.
 *
 * Padding uses crypto.randomBytes (not zeros) to prevent
 * compression-based oracles (CRIME/BREACH on TLS compression).
 *
 * Usage:
 *   reply.send(padResponse({ ... }));
 *   reply.send(padResponse({ ... }, 1024)); // custom target
 */

const DEFAULT_TARGET_SIZE = 512;
const FIELD_OVERHEAD = 7; // "_p":"" + comma

export function padResponse(
  body: Record<string, unknown>,
  targetSize: number = DEFAULT_TARGET_SIZE,
): Record<string, unknown> {
  const serialized = JSON.stringify(body);
  const deficit = targetSize - serialized.length;
  if (deficit <= FIELD_OVERHEAD) return body;
  const paddingLen = deficit - FIELD_OVERHEAD;
  const paddingBytes = randomBytes(Math.ceil(paddingLen * 0.75));
  return { ...body, _p: paddingBytes.toString("base64").slice(0, paddingLen) };
}
