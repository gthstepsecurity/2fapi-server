// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { FastifyInstance } from "fastify";
import type { VerifyProof } from "../../zk-verification/domain/port/incoming/verify-proof.js";
import type { IssueToken } from "../../api-access-control/domain/port/incoming/issue-token.js";
import { createProblemDetails } from "../problem-details.js";
import { getRequestId } from "../middleware/request-id.js";
import { isValidBase64, isValidClientIdentifier, isValidDomainSeparationTag, decodeBase64 } from "../validation.js";
import { padResponse } from "../response-padding.js";

interface VerificationBody {
  clientIdentifier?: string;
  challengeId?: string;
  proof?: string;
  channelBinding?: string;
  domainSeparationTag?: string;
  targetAudience?: string;
}

export function registerVerificationRoutes(
  app: FastifyInstance,
  verifyProof: VerifyProof,
  issueToken: IssueToken,
): void {
  app.post<{ Body: VerificationBody }>(
    "/v1/verify",
    async (request, reply) => {
      const requestId = getRequestId(request);
      const body = request.body as VerificationBody | null;

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
      const requiredStringFields: Array<{
        field: keyof VerificationBody;
        name: string;
        isBase64: boolean;
      }> = [
        { field: "clientIdentifier", name: "clientIdentifier", isBase64: false },
        { field: "challengeId", name: "challengeId", isBase64: false },
        { field: "proof", name: "proof", isBase64: true },
        { field: "channelBinding", name: "channelBinding", isBase64: true },
        {
          field: "domainSeparationTag",
          name: "domainSeparationTag",
          isBase64: false,
        },
      ];

      for (const { field, name, isBase64 } of requiredStringFields) {
        const value = body[field];
        if (value === undefined || value === null) {
          return reply
            .status(400)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:validation",
                "Bad Request",
                400,
                `Missing required field: ${name}`,
                requestId,
              ),
            );
        }

        if (typeof value !== "string" || value.length === 0) {
          return reply
            .status(400)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:validation",
                "Bad Request",
                400,
                `${name} must not be empty`,
                requestId,
              ),
            );
        }

        if (isBase64 && !isValidBase64(value)) {
          return reply
            .status(400)
            .header("Content-Type", "application/problem+json")
            .send(
              createProblemDetails(
                "urn:2fapi:error:validation",
                "Bad Request",
                400,
                `Invalid base64 encoding in field: ${name}`,
                requestId,
              ),
            );
        }
      }

      // FIX L-01: validate DST charset + length (was length-only, accepted Unicode)
      if (body.domainSeparationTag && !isValidDomainSeparationTag(body.domainSeparationTag)) {
        return reply
          .status(400)
          .header("Content-Type", "application/problem+json")
          .send(
            createProblemDetails(
              "urn:2fapi:error:validation",
              "Bad Request",
              400,
              "domainSeparationTag must be 1-64 ASCII chars [a-zA-Z0-9._-]",
              requestId,
            ),
          );
      }

      // Validate clientIdentifier format (consistent across all routes)
      if (!isValidClientIdentifier(body.clientIdentifier!)) {
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

      // At this point all fields are validated
      const clientIdentifier = body.clientIdentifier!;
      const challengeId = body.challengeId!;
      const proofBytes = decodeBase64(body.proof!);
      const channelBindingBytes = decodeBase64(body.channelBinding!);
      const domainSeparationTag = body.domainSeparationTag!;

      const verificationResult = await verifyProof.execute({
        clientIdentifier,
        challengeId,
        proofBytes,
        channelBinding: channelBindingBytes,
        domainSeparationTag,
      });

      if (!verificationResult.success) {
        // FIX H-02: all verification failures return identical 401.
        //
        // Previously rate_limited returned 429 — this allowed attackers to:
        //   (a) detect the rate-limit threshold per client,
        //   (b) distinguish "real" failures from throttled attempts,
        //   (c) time probing sessions around the window reset.
        //
        // Rate limiting is still enforced server-side; the 401 response
        // is intentionally indistinguishable from any other refusal.
        return reply
          .status(401)
          .header("Content-Type", "application/problem+json")
          .send(
            padResponse(
              createProblemDetails(
                "urn:2fapi:error:verification-refused",
                "Unauthorized",
                401,
                "Verification could not be completed",
                requestId,
              ),
            ),
          );
      }

      // Verification succeeded; issue an access token
      const channelBindingHash = Buffer.from(channelBindingBytes)
        .toString("base64");

      const tokenResult = await issueToken.execute({
        clientIdentifier: verificationResult.clientIdentifier,
        audience: body.targetAudience || "default",
        channelBindingHash,
        verificationReceiptId: verificationResult.receiptId,
      });

      if (!tokenResult.success) {
        // Token issuance failed after successful verification
        return reply
          .status(401)
          .header("Content-Type", "application/problem+json")
          .send(
            padResponse(
              createProblemDetails(
                "urn:2fapi:error:verification-refused",
                "Unauthorized",
                401,
                "Verification could not be completed",
                requestId,
              ),
            ),
          );
      }

      const expiresAt = new Date(tokenResult.expiresAtMs).toISOString();
      const expiresIn = Math.floor(
        (tokenResult.expiresAtMs - Date.now()) / 1000,
      );

      return reply
        .status(200)
        .header("Content-Type", "application/json; charset=utf-8")
        .send(
          padResponse({
            accessToken: tokenResult.bearerToken,
            tokenType: "Bearer",
            expiresAt,
            expiresIn: expiresIn > 0 ? expiresIn : 0,
          }),
        );
    },
  );
}
