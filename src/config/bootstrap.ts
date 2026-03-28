// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Application bootstrap.
 *
 * Detects the environment, creates the appropriate services,
 * and wires them into the Fastify API gateway.
 *
 * Usage:
 *   import { bootstrap } from "./config/bootstrap.js";
 *   const app = await bootstrap();
 *   await app.listen({ port: 3000, host: "0.0.0.0" });
 */

import type { FastifyInstance } from "fastify";
import { loadConfigFromEnv } from "./environment.js";
import type { AllServices } from "./development-services.js";
import { createServer, createDevelopmentServer } from "../api-gateway/server.js";

/**
 * Bootstraps the 2FApi application.
 *
 * In production:
 * - Connects to PostgreSQL and Redis
 * - Loads EdDSA signing key
 * - Creates all real infrastructure adapters
 * - Validates connectivity before returning
 *
 * In development/test:
 * - Uses in-memory adapters
 * - No external dependencies required
 *
 * @returns A configured Fastify instance ready to listen
 */
export async function bootstrap(): Promise<FastifyInstance> {
  const config = loadConfigFromEnv();
  const env = config.environment;

  console.log(`[BOOT] Environment: ${env}`);
  console.log(`[BOOT] Server port: ${config.server.port}`);
  console.log(`[BOOT] Channel binding: ${config.server.channelBindingMode}`);

  let services: AllServices;

  if (env === "production") {
    const { createProductionServices } = await import("./production-services.js");
    services = await createProductionServices(config);

    console.log("[BOOT] Rate limiting: global=%d/%dms, ip=%d/%dms",
      config.rateLimiting.globalMaxRequests,
      config.rateLimiting.globalWindowMs,
      config.rateLimiting.perIpMaxRequests,
      config.rateLimiting.perIpWindowMs,
    );
    console.log("[BOOT] Lockout: threshold=%d, duration=%dms",
      config.lockout.threshold,
      config.lockout.durationMs,
    );
    console.log("[BOOT] Recovery: mode=%s, words=%d",
      config.recovery.mode,
      config.recovery.wordCount,
    );

    const app = createServer(
      {
        enrollClient: services.enrollClient,
        requestChallenge: services.requestChallenge,
        verifyProof: services.verifyProof,
        issueToken: services.issueToken,
        validateToken: services.validateToken,
        revokeClient: services.revokeClient,
        rotateCommitment: services.rotateCommitment,
        recoverViaPhrase: services.recoverViaPhrase,
        reactivateViaExternal: services.reactivateViaExternal,
      },
      {
        rateLimiting: {
          globalRateLimiter: services.globalRateLimiter,
          ipRateLimiter: services.ipRateLimiter,
          trustedProxies: [],
        },
        channelBindingMode: config.server.channelBindingMode,
      },
    );

    console.log("[BOOT] Production server ready");
    return app;
  }

  // Development / Test
  const { createDevelopmentServices } = await import("./development-services.js");
  services = createDevelopmentServices();

  console.log("[BOOT] Using in-memory adapters (development mode)");

  const app = createDevelopmentServer(
    {
      enrollClient: services.enrollClient,
      requestChallenge: services.requestChallenge,
      verifyProof: services.verifyProof,
      issueToken: services.issueToken,
      validateToken: services.validateToken,
      revokeClient: services.revokeClient,
      rotateCommitment: services.rotateCommitment,
      recoverViaPhrase: services.recoverViaPhrase,
      reactivateViaExternal: services.reactivateViaExternal,
    },
    {
      channelBindingMode: config.server.channelBindingMode,
    },
  );

  console.log("[BOOT] Development server ready");
  return app;
}
