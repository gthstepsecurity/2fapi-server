// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { RecoverViaPhrase } from "../../client-registration/domain/port/incoming/recover-via-phrase.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { isValidBase64, isValidClientIdentifier, decodeBase64 } from "../validation.js";

interface RecoveryBody {
  recoveryWords?: string[];
  newCommitment?: string;
  newCommitmentProof?: string;
}

export function registerRecoveryRoutes(
  app: FastifyInstance,
  recoverViaPhrase: RecoverViaPhrase,
): void {
  app.post<{ Params: { clientId: string }; Body: RecoveryBody }>(
    "/v1/clients/:clientId/recover",
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

      const body = request.body as RecoveryBody | null;

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

      // Validate recoveryWords
      if (!body.recoveryWords || !Array.isArray(body.recoveryWords)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: recoveryWords",
              requestId,
            ),
          );
      }

      // CB09: Validate recovery words count is exactly 12, 18, or 24 (BIP-39 standard)
      const validWordCounts = [12, 18, 24];
      if (!validWordCounts.includes(body.recoveryWords.length)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "recoveryWords must contain exactly 12, 18, or 24 words",
              requestId,
            ),
          );
      }

      if (body.recoveryWords.length === 0 || !body.recoveryWords.every((w) => typeof w === "string" && w.length > 0)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "recoveryWords must be a non-empty array of non-empty strings",
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

      const result = await recoverViaPhrase.execute({
        clientIdentifier: clientId,
        words: body.recoveryWords,
        newCommitmentBytes: decodeBase64(body.newCommitment),
        newCommitmentProofBytes: decodeBase64(body.newCommitmentProof),
      });

      if (result.success) {
        return reply
          .status(200)
          .header("Content-Type", "application/json; charset=utf-8")
          .send({
            recovered: true,
            clientIdentifier: clientId,
          });
      }

      // Indistinguishable failure response
      return reply
        .status(401)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:recovery-failed",
            "Unauthorized",
            401,
            "recovery_failed",
            requestId,
          ),
        );
    },
  );
}
