// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { ReactivateViaExternal } from "../../client-registration/domain/port/incoming/reactivate-via-external.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { isValidBase64, isValidClientIdentifier, decodeBase64 } from "../validation.js";

interface ReactivationBody {
  newCommitment?: string;
  newCommitmentProof?: string;
}

export function registerReactivationRoutes(
  app: FastifyInstance,
  reactivateViaExternal: ReactivateViaExternal,
): void {
  app.post<{ Params: { clientId: string }; Body: ReactivationBody }>(
    "/v1/clients/:clientId/reactivate",
    async (request, reply) => {
      const requestId = getRequestId(request);
      const clientId = request.params.clientId;

      // Validate clientId format
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

      // Check for admin identity (X-Admin-Identity header)
      const adminIdentity = request.headers["x-admin-identity"] as
        | string
        | undefined;

      if (!adminIdentity) {
        return reply
          .status(403)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:forbidden",
              "Forbidden",
              403,
              "Administrator privileges required",
              requestId,
            ),
          );
      }

      const body = request.body as ReactivationBody | null;

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

      // Validate newCommitment
      if (body.newCommitment === undefined || body.newCommitment === null) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: newCommitment",
              requestId,
            ),
          );
      }

      if (typeof body.newCommitment !== "string" || !isValidBase64(body.newCommitment)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Invalid base64 encoding in field: newCommitment",
              requestId,
            ),
          );
      }

      // Validate newCommitmentProof
      if (body.newCommitmentProof === undefined || body.newCommitmentProof === null) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: newCommitmentProof",
              requestId,
            ),
          );
      }

      if (typeof body.newCommitmentProof !== "string" || !isValidBase64(body.newCommitmentProof)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Invalid base64 encoding in field: newCommitmentProof",
              requestId,
            ),
          );
      }

      const result = await reactivateViaExternal.execute({
        clientIdentifier: clientId,
        adminIdentity,
        newCommitmentBytes: decodeBase64(body.newCommitment),
        newCommitmentProofBytes: decodeBase64(body.newCommitmentProof),
      });

      if (result.success) {
        return reply
          .status(200)
          .header("Content-Type", "application/json; charset=utf-8")
          .send({
            reactivated: true,
          });
      }

      // Indistinguishable failure response
      return reply
        .status(401)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:reactivation-failed",
            "Unauthorized",
            401,
            "reactivation_failed",
            requestId,
          ),
        );
    },
  );
}
