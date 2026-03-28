// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { GlobalRateLimiter } from "../../shared/global-rate-limiter.js";
import type { IpRateLimiter } from "./ip-rate-limiter.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "./request-id.js";

export interface RateLimitHookDependencies {
  readonly globalRateLimiter?: GlobalRateLimiter;
  readonly ipRateLimiter?: IpRateLimiter;
  readonly trustedProxies: string[];
}

/**
 * Fastify onRequest hook that enforces global and per-IP rate limits.
 *
 * Evaluation order:
 * 1. Global rate limit (shared across all clients)
 * 2. Per-IP rate limit (per source IP)
 *
 * On rejection, responds with HTTP 429 and a Problem Details body
 * including a Retry-After header.
 */
export function registerRateLimitHook(
  app: FastifyInstance,
  deps: RateLimitHookDependencies,
): void {
  app.addHook("onRequest", async (request, reply) => {
    const requestId = getRequestId(request);

    // 1. Global rate limit
    if (deps.globalRateLimiter) {
      const globalResult = deps.globalRateLimiter.tryAcquire();
      if (!globalResult.allowed) {
        return reply
          .status(429)
          .header("Content-Type", "application/problem+json")
          .header("Retry-After", String(Math.ceil(globalResult.retryAfterSeconds ?? 1)))
          .send(
            createProblemDetails(
              "urn:2fapi:error:rate-limit-exceeded",
              "Too Many Requests",
              429,
              "Global rate limit exceeded",
              requestId,
            ),
          );
      }
    }

    // 2. Per-IP rate limit
    if (deps.ipRateLimiter) {
      const connectionIp = request.ip;
      const xForwardedFor = request.headers["x-forwarded-for"] as string | undefined;
      const realIp = deps.ipRateLimiter.extractRealIp(
        connectionIp,
        xForwardedFor,
        deps.trustedProxies,
      );

      const ipResult = deps.ipRateLimiter.tryAcquire(realIp);

      if (!ipResult.allowed) {
        return reply
          .status(429)
          .header("Content-Type", "application/problem+json")
          .header("Retry-After", String(Math.ceil(ipResult.retryAfterSeconds ?? 1)))
          .header("X-RateLimit-Limit", String(ipResult.limit))
          .header("X-RateLimit-Remaining", "0")
          .send(
            createProblemDetails(
              "urn:2fapi:error:rate-limit-exceeded",
              "Too Many Requests",
              429,
              "Per-IP rate limit exceeded",
              requestId,
            ),
          );
      }

      // Add rate limit headers when approaching threshold
      if (ipResult.remaining <= Math.ceil(ipResult.limit * 0.2)) {
        void reply.header("X-RateLimit-Limit", String(ipResult.limit));
        void reply.header("X-RateLimit-Remaining", String(ipResult.remaining));
      }
    }
  });
}
