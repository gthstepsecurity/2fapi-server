// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "./request-id.js";

const METHODS_REQUIRING_CONTENT_TYPE = new Set(["POST", "PUT", "PATCH"]);

export function registerContentTypeCheck(app: FastifyInstance): void {
  app.addHook("preHandler", async (request, reply) => {
    if (!METHODS_REQUIRING_CONTENT_TYPE.has(request.method)) {
      return;
    }

    const contentType = request.headers["content-type"];
    if (
      typeof contentType !== "string" ||
      !contentType.startsWith("application/json")
    ) {
      const requestId = getRequestId(request);
      void reply
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
  });
}
