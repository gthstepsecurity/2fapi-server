// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";

export function registerHealthRoutes(app: FastifyInstance): void {
  app.get("/health", async (_request, reply) => {
    return reply
      .status(200)
      .header("Content-Type", "application/json; charset=utf-8")
      .send({
        status: "ok",
        version: "1.0",
      });
  });

  app.get("/v1/openapi.json", async (_request, reply) => {
    return reply
      .status(200)
      .header("Content-Type", "application/json; charset=utf-8")
      .send({
        openapi: "3.1.0",
        info: {
          title: "2FApi — Zero-Knowledge Proof Authentication API",
          version: "1.0.0",
          description:
            "Fast 2FA-like protocol using Pedersen commitments for API call validation",
        },
        paths: {
          "/v1/clients": {
            post: { summary: "Enroll a new client" },
          },
          "/v1/challenges": {
            post: { summary: "Request an authentication challenge" },
          },
          "/v1/verify": {
            post: { summary: "Submit a zero-knowledge proof" },
          },
          "/v1/resources/{resourceId}": {
            get: { summary: "Access a protected resource" },
          },
        },
      });
  });
}
