// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { EnrollClient } from "../../client-registration/domain/port/incoming/enroll-client.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import {
  isValidBase64,
  isValidClientIdentifier,
  decodeBase64,
} from "../validation.js";

interface EnrollmentBody {
  clientIdentifier?: string;
  commitment?: string;
  proofOfPossession?: string;
}

export function registerEnrollmentRoutes(
  app: FastifyInstance,
  enrollClient: EnrollClient,
): void {
  app.post<{ Body: EnrollmentBody }>("/v1/clients", async (request, reply) => {
    const requestId = getRequestId(request);
    const body = request.body as EnrollmentBody | null;

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

    if (typeof body.clientIdentifier !== "string" || body.clientIdentifier.length === 0) {
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

    if (body.clientIdentifier.length > 128) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "clientIdentifier exceeds maximum length of 128 characters",
            requestId,
          ),
        );
    }

    if (!isValidClientIdentifier(body.clientIdentifier)) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "clientIdentifier contains invalid characters",
            requestId,
          ),
        );
    }

    if (body.commitment === undefined || body.commitment === null) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "Missing required field: commitment",
            requestId,
          ),
        );
    }

    if (typeof body.commitment !== "string" || !isValidBase64(body.commitment)) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "Invalid base64 encoding in field: commitment",
            requestId,
          ),
        );
    }

    if (
      body.proofOfPossession === undefined ||
      body.proofOfPossession === null
    ) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "Missing required field: proofOfPossession",
            requestId,
          ),
        );
    }

    if (
      typeof body.proofOfPossession !== "string" ||
      !isValidBase64(body.proofOfPossession)
    ) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            "Invalid base64 encoding in field: proofOfPossession",
            requestId,
          ),
        );
    }

    // Convert to domain types
    const commitmentBytes = decodeBase64(body.commitment);
    const proofBytes = decodeBase64(body.proofOfPossession);

    // The proof of possession is encoded as 3x32 bytes = 96 bytes (announcement + responseS + responseR)
    const announcement = proofBytes.slice(0, 32);
    const responseS = proofBytes.slice(32, 64);
    const responseR = proofBytes.slice(64, 96);

    const result = await enrollClient.execute({
      clientIdentifier: body.clientIdentifier,
      commitmentBytes,
      proofOfPossession: {
        announcement,
        responseS,
        responseR,
      },
    });

    if (result.success) {
      return reply
        .status(201)
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Location", `/v1/clients/${result.referenceId}`)
        .send({
          referenceId: result.referenceId,
          clientIdentifier: result.clientIdentifier,
        });
    }

    // Domain refusal: return indistinguishable 409
    return reply
      .status(409)
      .header("Content-Type", "application/problem+json")
      .send(
        createProblemDetails(
          "urn:2fapi:error:enrollment-refused",
          "Enrollment Refused",
          409,
          "Enrollment could not be completed",
          requestId,
        ),
      );
  });
}
