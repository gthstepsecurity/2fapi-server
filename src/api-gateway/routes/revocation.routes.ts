// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { RevokeClient } from "../../client-registration/domain/port/incoming/revoke-client.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { isValidClientIdentifier } from "../validation.js";

export function registerRevocationRoutes(
  app: FastifyInstance,
  revokeClient: RevokeClient,
): void {
  app.delete<{ Params: { clientId: string } }>(
    "/v1/clients/:clientId",
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

      // Execute revocation use case
      await revokeClient.execute({
        clientIdentifier: clientId,
        adminIdentity,
      });

      // Always return 204 (indistinguishable for unknown clients)
      return reply.status(204).send();
    },
  );
}
