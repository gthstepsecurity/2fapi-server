// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";
import type { FastifyInstance } from "fastify";

/**
 * Global response padding middleware.
 *
 * Pads ALL JSON responses on /v1/ routes to a uniform byte size.
 * This prevents a TLS record size oracle — an observer cannot determine
 * which endpoint was called or whether the request succeeded by measuring
 * the encrypted record length.
 *
 * Applied as an onSend hook (after route handler, before socket flush).
 * Works on the SERIALIZED JSON string, not the object — no interaction
 * with route-level padResponse() calls (which become redundant but harmless).
 *
 * Padding uses crypto.randomBytes (not zeros) to defeat CRIME/BREACH
 * compression oracles.
 */

const DEFAULT_TARGET_SIZE = 1024;
const PADDING_KEY = ',"_p":"';
const PADDING_KEY_END = '"';
// Total overhead: ,"_p":"..." = PADDING_KEY + content + PADDING_KEY_END

export interface ResponsePaddingOptions {
  /** Target body size in bytes. Default: 1024. */
  readonly targetSize?: number;
  /** Route prefixes to pad. Default: ["/v1/"]. */
  readonly prefixes?: string[];
}

export function registerResponsePaddingHook(
  app: FastifyInstance,
  options?: ResponsePaddingOptions,
): void {
  const targetSize = options?.targetSize ?? DEFAULT_TARGET_SIZE;
  const prefixes = options?.prefixes ?? ["/v1/"];

  app.addHook("onSend", async (request, reply, payload) => {
    // Only pad JSON responses on matching routes
    const url = request.url;
    if (!prefixes.some((p) => url.startsWith(p))) return payload;

    const contentType = reply.getHeader("content-type") as string | undefined;
    if (!contentType?.includes("json")) return payload;

    // payload is already serialized by Fastify
    if (typeof payload !== "string") return payload;

    const currentSize = Buffer.byteLength(payload, "utf-8");
    if (currentSize >= targetSize) return payload;

    // Calculate padding needed
    const overhead = PADDING_KEY.length + PADDING_KEY_END.length;
    const deficit = targetSize - currentSize - overhead;
    if (deficit <= 0) return payload;

    // Generate random base64 padding
    const paddingBytes = randomBytes(Math.ceil(deficit * 0.75));
    const paddingStr = paddingBytes.toString("base64").slice(0, deficit);

    // Inject padding field before the closing brace
    // {"type":"...","status":401} → {"type":"...","status":401,"_p":"..."}
    const lastBrace = payload.lastIndexOf("}");
    if (lastBrace === -1) return payload;

    return (
      payload.slice(0, lastBrace) +
      PADDING_KEY +
      paddingStr +
      PADDING_KEY_END +
      payload.slice(lastBrace)
    );
  });
}
