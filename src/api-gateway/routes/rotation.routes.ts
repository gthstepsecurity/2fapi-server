// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { RotateCommitment } from "../../client-registration/domain/port/incoming/rotate-commitment.js";
import type { ValidateToken } from "../../api-access-control/domain/port/incoming/validate-token.js";
import type { ChannelBindingMode } from "../server.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { isValidBase64, isValidClientIdentifier, decodeBase64 } from "../validation.js";

interface RotationBody {
  currentProof?: string;
  newCommitment?: string;
  newCommitmentProof?: string;
}

function extractBearerToken(
  authHeader: string | undefined,
): string | null {
  if (!authHeader) return null;
  const match = /^bearer\s+(.+)$/i.exec(authHeader);
  if (!match) return null;
  return match[1] ?? null;
}

export function registerRotationRoutes(
  app: FastifyInstance,
  rotateCommitment: RotateCommitment,
  validateToken: ValidateToken,
  serviceAudience: string,
  channelBindingMode: ChannelBindingMode = "permissive",
): void {
  app.put<{ Params: { clientId: string }; Body: RotationBody }>(
    "/v1/clients/:clientId/commitment",
    async (request, reply) => {
      const requestId = getRequestId(request);
      const clientId = request.params.clientId;

      // Validate clientId format (consistent across all routes)
      if (!isValidClientIdentifier(clientId)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Invalid client identifier format",
              requestId,
            ),
          );
      }

      // Check Bearer token
      const authHeader = request.headers["authorization"] as
        | string
        | undefined;

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

      // Validate token — check that token was issued for this service
      const tokenResult = await validateToken.execute({
        bearerToken: token,
        channelBindingHash,
        expectedAudience: serviceAudience,
      });

      if (!tokenResult.success) {
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

      // Validate body
      const body = request.body as RotationBody | null;

      if (!body || typeof body !== "object") {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Request body is required",
              requestId,
            ),
          );
      }

      // Required fields
      const base64Fields: Array<{
        field: keyof RotationBody;
        name: string;
      }> = [
        { field: "currentProof", name: "currentProof" },
        { field: "newCommitment", name: "newCommitment" },
        { field: "newCommitmentProof", name: "newCommitmentProof" },
      ];

      for (const { field, name } of base64Fields) {
        const value = body[field];
        if (value === undefined || value === null) {
          return reply
            .status(400)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:validation",
                "Bad Request",
                400,
                `Missing required field: ${name}`,
                requestId,
              ),
            );
        }

        if (typeof value !== "string" || !isValidBase64(value)) {
          return reply
            .status(400)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:validation",
                "Bad Request",
                400,
                `Invalid base64 encoding in field: ${name}`,
                requestId,
              ),
            );
        }
      }

      const result = await rotateCommitment.execute({
        clientIdentifier: clientId,
        currentProofBytes: decodeBase64(body.currentProof!),
        newCommitmentBytes: decodeBase64(body.newCommitment!),
        newCommitmentProofBytes: decodeBase64(body.newCommitmentProof!),
      });

      if (result.success) {
        return reply
          .status(200)
          .header("Content-Type", "application/json; charset=utf-8")
          .send({
            rotatedAt: new Date().toISOString(),
          });
      }

      // Indistinguishable 401 for rotation failures
      return reply
        .status(401)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:rotation-refused",
            "Unauthorized",
            401,
            "Rotation could not be completed",
            requestId,
          ),
        );
    },
  );
}
