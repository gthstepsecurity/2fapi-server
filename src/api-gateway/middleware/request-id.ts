// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomUUID } from "node:crypto";
import type { FastifyInstance, FastifyRequest } from "fastify";

declare module "fastify" {
  interface FastifyRequest {
    requestId: string;
  }
}

const MAX_REQUEST_ID_LENGTH = 128;
const VALID_REQUEST_ID_REGEX = /^[a-zA-Z0-9-]+$/;

/**
 * Validates a client-provided X-Request-Id.
 * Accepts: alphanumeric characters and hyphens, max 128 characters.
 * Returns false for empty, oversized, or special-character values.
 */
function isValidRequestId(value: string): boolean {
  if (value.length === 0 || value.length > MAX_REQUEST_ID_LENGTH) {
    return false;
  }
  return VALID_REQUEST_ID_REGEX.test(value);
}

export function registerRequestIdHook(app: FastifyInstance): void {
  app.decorateRequest("requestId", "");

  app.addHook("onRequest", async (request, reply) => {
    const clientId = request.headers["x-request-id"];
    const requestId =
      typeof clientId === "string" && isValidRequestId(clientId)
        ? clientId
        : randomUUID();
    request.requestId = requestId;
    void reply.header("X-Request-Id", requestId);
  });
}

export function getRequestId(request: FastifyRequest): string {
  return request.requestId ?? randomUUID();
}
