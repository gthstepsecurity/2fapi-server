// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance, FastifyError } from "fastify";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "./request-id.js";

function isFastifyError(error: unknown): error is FastifyError {
  return typeof error === "object" && error !== null && "code" in error;
}

export function registerErrorHandler(app: FastifyInstance): void {
  app.setErrorHandler(async (error, request, reply) => {
    const requestId = getRequestId(request);
    const err = isFastifyError(error) ? error : null;

    // Fastify content-type validation error
    if (err?.code === "FST_ERR_CTP_INVALID_MEDIA_TYPE") {
      return reply
        .status(415)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:unsupported-media-type",
            "Unsupported Media Type",
            415,
            "Content-Type must be application/json",
            requestId,
          ),
        );
    }

    if (err?.validation) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:validation",
            "Bad Request",
            400,
            err.message,
            requestId,
          ),
        );
    }

    if (
      err?.statusCode === 400 &&
      (err.message.includes("JSON") ||
        err.message.includes("Unexpected") ||
        err.code === "FST_ERR_CTP_INVALID_CONTENT_LENGTH")
    ) {
      return reply
        .status(400)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:malformed-body",
            "Bad Request",
            400,
            "Request body is not valid JSON",
            requestId,
          ),
        );
    }

    if (err?.statusCode === 413) {
      return reply
        .status(413)
        .header("Content-Type", "application/problem+json")
        .send(
          createProblemDetails(
            "urn:2fapi:error:payload-too-large",
            "Payload Too Large",
            413,
            "Request body must not exceed 65536 bytes",
            requestId,
          ),
        );
    }

    // Default: 500 Internal Server Error
    return reply
      .status(500)
      .header("Content-Type", "application/problem+json")
      .send(
        createProblemDetails(
          "urn:2fapi:error:internal",
          "Internal Server Error",
          500,
          "An unexpected error occurred",
          requestId,
        ),
      );
  });
}
