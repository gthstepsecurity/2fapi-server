// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";

export function registerNotFoundHandler(app: FastifyInstance): void {
  app.setNotFoundHandler(async (request, reply) => {
    const requestId = getRequestId(request);
    const path = request.url;

    const detail = path.startsWith("/v1/")
      ? "The requested resource was not found"
      : "Use versioned API paths, e.g. /v1/clients";

    return reply
      .status(404)
      .header("Content-Type", "application/problem+json")
      .send(
        createProblemDetails(
          "urn:2fapi:error:not-found",
          "Not Found",
          404,
          detail,
          requestId,
        ),
      );
  });
}
