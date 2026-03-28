// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import Fastify, { type FastifyInstance } from "fastify";
import type { EnrollClient } from "../client-registration/domain/port/incoming/enroll-client.js";
import type { RequestChallenge } from "../authentication-challenge/domain/port/incoming/request-challenge.js";
import type { VerifyProof } from "../zk-verification/domain/port/incoming/verify-proof.js";
import type { IssueToken } from "../api-access-control/domain/port/incoming/issue-token.js";
import type { ValidateToken } from "../api-access-control/domain/port/incoming/validate-token.js";
import type { RevokeClient } from "../client-registration/domain/port/incoming/revoke-client.js";
import type { RotateCommitment } from "../client-registration/domain/port/incoming/rotate-commitment.js";
import type { RecoverViaPhrase } from "../client-registration/domain/port/incoming/recover-via-phrase.js";
import type { ReactivateViaExternal } from "../client-registration/domain/port/incoming/reactivate-via-external.js";
import type { GlobalRateLimiter } from "../shared/global-rate-limiter.js";
import type { IpRateLimiter } from "./middleware/ip-rate-limiter.js";
import { registerRequestIdHook } from "./middleware/request-id.js";
import { registerSecurityHeaders } from "./middleware/security-headers.js";
import { registerContentTypeCheck } from "./middleware/content-type.js";
import { registerErrorHandler } from "./middleware/error-handler.js";
import { registerRateLimitHook } from "./middleware/rate-limit-hook.js";
import { registerHealthRoutes } from "./routes/health.routes.js";
import { registerEnrollmentRoutes } from "./routes/enrollment.routes.js";
import { registerChallengeRoutes } from "./routes/challenge.routes.js";
import { registerVerificationRoutes } from "./routes/verification.routes.js";
import { registerResourceRoutes } from "./routes/resource.routes.js";
import { registerRevocationRoutes } from "./routes/revocation.routes.js";
import { registerRotationRoutes } from "./routes/rotation.routes.js";
import { registerRecoveryRoutes } from "./routes/recovery.routes.js";
import { registerReactivationRoutes } from "./routes/reactivation.routes.js";
import { registerNotFoundHandler } from "./routes/not-found.handler.js";
import { registerResponseTimingNormalizer } from "./middleware/response-timing-normalizer.js";
import { registerResponsePaddingHook } from "./middleware/response-padding-hook.js";

export interface ApiGatewayDependencies {
  readonly enrollClient: EnrollClient;
  readonly requestChallenge: RequestChallenge;
  readonly verifyProof: VerifyProof;
  readonly issueToken: IssueToken;
  readonly validateToken: ValidateToken;
  readonly revokeClient: RevokeClient;
  readonly rotateCommitment: RotateCommitment;
  readonly recoverViaPhrase?: RecoverViaPhrase;
  readonly reactivateViaExternal?: ReactivateViaExternal;
}

export interface RateLimitDependencies {
  readonly globalRateLimiter?: GlobalRateLimiter;
  readonly ipRateLimiter?: IpRateLimiter;
  readonly trustedProxies?: string[];
}

export type ChannelBindingMode = "strict" | "permissive";

export interface ServerOptions {
  readonly bodyLimit?: number;
  readonly rateLimiting?: RateLimitDependencies;
  readonly serviceAudience?: string;
  readonly channelBindingMode?: ChannelBindingMode;
}

export function createServer(
  deps: ApiGatewayDependencies,
  options?: ServerOptions,
): FastifyInstance {
  // Rate limiting is required for production deployment
  if (!options?.rateLimiting) {
    throw new Error(
      "Rate limiting configuration is required for production deployment. " +
      "Use createDevelopmentServer() for development environments with permissive defaults.",
    );
  }

  return createServerInternal(deps, options);
}

/**
 * Creates a server with permissive defaults suitable for development.
 * NOT for production use — uses no rate limiting.
 */
export function createDevelopmentServer(
  deps: ApiGatewayDependencies,
  options?: Partial<ServerOptions>,
): FastifyInstance {
  return createServerInternal(deps, {
    bodyLimit: options?.bodyLimit ?? 65536,
    rateLimiting: options?.rateLimiting ?? { trustedProxies: [] },
    serviceAudience: options?.serviceAudience ?? "development",
    channelBindingMode: options?.channelBindingMode ?? "permissive",
  });
}

function createServerInternal(
  deps: ApiGatewayDependencies,
  options?: ServerOptions,
): FastifyInstance {
  const app = Fastify({
    bodyLimit: options?.bodyLimit ?? 65536,
    logger: false,
    // I-11: Set socket timeouts to prevent connection exhaustion attacks
    connectionTimeout: 30_000,  // 30s to establish connection
    keepAliveTimeout: 5_000,    // 5s keep-alive between requests
  });

  // Middleware (order matters)
  registerRequestIdHook(app);
  registerSecurityHeaders(app);
  registerResponseTimingNormalizer(app); // FIX RT-DL-05: uniform response timing
  registerResponsePaddingHook(app);    // FIX RT-36: uniform response size (1024 bytes)
  registerErrorHandler(app);
  registerContentTypeCheck(app);

  // Rate limiting (optional — only wired when dependencies are provided)
  if (options?.rateLimiting) {
    const rl = options.rateLimiting;
    registerRateLimitHook(app, {
      trustedProxies: rl.trustedProxies ?? [],
      ...(rl.globalRateLimiter ? { globalRateLimiter: rl.globalRateLimiter } : {}),
      ...(rl.ipRateLimiter ? { ipRateLimiter: rl.ipRateLimiter } : {}),
    });
  }

  // Routes
  registerHealthRoutes(app);
  registerEnrollmentRoutes(app, deps.enrollClient);
  registerChallengeRoutes(app, deps.requestChallenge);
  registerVerificationRoutes(app, deps.verifyProof, deps.issueToken);
  const serviceAudience = options?.serviceAudience ?? "default";
  // CF01: Default to strict channel binding to prevent token misuse across connections
  const channelBindingMode = options?.channelBindingMode ?? "strict";
  registerResourceRoutes(app, deps.validateToken, serviceAudience, channelBindingMode);
  registerRevocationRoutes(app, deps.revokeClient);
  registerRotationRoutes(app, deps.rotateCommitment, deps.validateToken, serviceAudience, channelBindingMode);
  if (deps.recoverViaPhrase) {
    registerRecoveryRoutes(app, deps.recoverViaPhrase);
  }
  if (deps.reactivateViaExternal) {
    registerReactivationRoutes(app, deps.reactivateViaExternal);
  }

  // 404 handler for unknown routes
  registerNotFoundHandler(app);

  return app;
}
