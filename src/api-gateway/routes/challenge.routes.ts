// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { RequestChallenge, RequestChallengeRequest } from "../../authentication-challenge/domain/port/incoming/request-challenge.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import {
  isValidBase64,
  isValidClientIdentifier,
  decodeBase64,
} from "../validation.js";

interface ChallengeBody {
  clientIdentifier?: string;
  credential?: string;
  channelBinding?: string;
  protocolVersion?: string;
}

export function registerChallengeRoutes(
  app: FastifyInstance,
  requestChallenge: RequestChallenge,
): void {
  app.post<{ Body: ChallengeBody }>(
    "/v1/challenges",
    async (request, reply) => {
      const requestId = getRequestId(request);
      const body = request.body as ChallengeBody | null;

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

      // Validate required fields
      if (
        body.clientIdentifier === undefined ||
        body.clientIdentifier === null
      ) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: clientIdentifier",
              requestId,
            ),
          );
      }

      if (
        typeof body.clientIdentifier !== "string" ||
        body.clientIdentifier.length === 0
      ) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "clientIdentifier must not be empty",
              requestId,
            ),
          );
      }

      // Validate clientIdentifier format (consistent across all routes)
      if (!isValidClientIdentifier(body.clientIdentifier)) {
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

      if (body.credential === undefined || body.credential === null) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: credential",
              requestId,
            ),
          );
      }

      if (
        typeof body.credential !== "string" ||
        !isValidBase64(body.credential)
      ) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Invalid base64 encoding in field: credential",
              requestId,
            ),
          );
      }

      if (body.channelBinding === undefined || body.channelBinding === null) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Missing required field: channelBinding",
              requestId,
            ),
          );
      }

      if (
        typeof body.channelBinding !== "string" ||
        !isValidBase64(body.channelBinding)
      ) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "Invalid base64 encoding in field: channelBinding",
              requestId,
            ),
          );
      }

      // Convert to domain types — build request conditionally to avoid passing undefined
      // with exactOptionalPropertyTypes
      const challengeRequest: RequestChallengeRequest = {
        clientIdentifier: body.clientIdentifier,
        credential: decodeBase64(body.credential),
        channelBinding: decodeBase64(body.channelBinding),
        ...(body.protocolVersion !== undefined
          ? { protocolVersion: body.protocolVersion }
          : {}),
      };
      const result = await requestChallenge.execute(challengeRequest);

      if (result.success) {
        const nonceBase64 = Buffer.from(result.nonce).toString("base64");
        const channelBindingBase64 = Buffer.from(result.channelBinding).toString("base64");

        return reply
          .status(200)
          .header("Content-Type", "application/json; charset=utf-8")
          .send({
            challengeId: result.challengeId,
            nonce: nonceBase64,
            channelBinding: channelBindingBase64,
            expiresAt: new Date(result.expiresAtMs).toISOString(),
            protocolVersion: result.protocolVersion,
          });
      }

      // Handle specific error codes
      if (result.error === "unsupported_protocol_version") {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:unsupported-version",
              "Bad Request",
              400,
              `Protocol version '${body.protocolVersion ?? ""}' is not supported`,
              requestId,
              {
                supportedVersions: result.supportedVersions
                  ? [...result.supportedVersions]
                  : ["1.0"],
              },
            ),
          );
      }

      if (result.error === "rate_limited") {
        return reply
          .status(429)
          .header("Content-Type", "application/problem+json")
          .header("Retry-After", "60")
          .send(
            createProblemDetails(
              "urn:2fapi:error:rate-limited",
              "Too Many Requests",
              429,
              "Rate limit exceeded, retry later",
              requestId,
            ),
          );
      }

      // Indistinguishable 401 for all other failures
      return reply
        .status(401)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:challenge-refused",
            "Unauthorized",
            401,
            "Challenge request could not be completed",
            requestId,
          ),
        );
    },
  );
}
