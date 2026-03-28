// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { ValidateToken } from "../../api-access-control/domain/port/incoming/validate-token.js";
import type { ChannelBindingMode } from "../server.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";

function extractBearerToken(
  authHeader: string | undefined,
): string | null {
  if (!authHeader) return null;
  const match = /^bearer\s+(.+)$/i.exec(authHeader);
  if (!match) return null;
  return match[1] ?? null;
}

export function registerResourceRoutes(
  app: FastifyInstance,
  validateToken: ValidateToken,
  serviceAudience: string,
  channelBindingMode: ChannelBindingMode = "permissive",
): void {
  app.get<{ Params: { resourceId: string } }>(
    "/v1/resources/:resourceId",
    async (request, reply) => {
      const requestId = getRequestId(request);
      const authHeader = request.headers["authorization"] as
        | string
        | undefined;
      const resourceId = request.params.resourceId;

      // Check for Bearer token
      if (!authHeader) {
        return reply
          .status(401)
          .header("WWW-Authenticate", 'Bearer realm="2fapi"')
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:unauthorized",
              "Unauthorized",
              401,
              "Bearer token required",
              requestId,
            ),
          );
      }

      const token = extractBearerToken(authHeader);
      if (!token) {
        return reply
          .status(401)
          .header("WWW-Authenticate", 'Bearer realm="2fapi"')
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:unauthorized",
              "Unauthorized",
              401,
              "Invalid authorization scheme, Bearer required",
              requestId,
            ),
          );
      }

      // Channel binding extraction
      const channelBindingHeader = request.headers["x-channel-binding"] as string | undefined;
      let channelBindingHash: string;
      if (channelBindingMode === "strict") {
        if (!channelBindingHeader) {
          return reply
            .status(401)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:unauthorized",
                "Unauthorized",
                401,
                "Missing required X-Channel-Binding header for channel binding verification",
                requestId,
              ),
            );
        }
        channelBindingHash = channelBindingHeader;
      } else {
        channelBindingHash = channelBindingHeader ?? "__channel_binding_skipped__";
      }

      // Validate token
      const result = await validateToken.execute({
        bearerToken: token,
        channelBindingHash,
        expectedAudience: serviceAudience,
      });

      if (!result.success) {
        // Token validation failed — we cannot distinguish between
        // expired, forged, wrong audience, etc. from the outside.
        // The domain only returns "access_denied".
        // We use 403 for known-but-unauthorized, 401 for invalid/expired tokens.
        return reply
          .status(401)
          .header(
            "WWW-Authenticate",
            'Bearer realm="2fapi", error="invalid_token"',
          )
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:unauthorized",
              "Unauthorized",
              401,
              "Access denied",
              requestId,
            ),
          );
      }

      // Token valid — return resource data
      return reply
        .status(200)
        .header("Content-Type", "application/json; charset=utf-8")
        .send({
          resourceId,
          clientIdentifier: result.clientIdentifier,
          audience: result.audience,
          data: {},
        });
    },
  );
}
