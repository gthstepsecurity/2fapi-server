// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { EnrollmentToken } from "../../model/enrollment-token.js";

/** Driven port — persistence for enrollment tokens. */
export interface EnrollmentTokenStore {
  save(token: EnrollmentToken): Promise<void>;
  findByValue(value: string): Promise<EnrollmentToken | null>;

  /**
   * FIX RT-DL-06: atomically consume a token (single-use enforcement).
   *
   * Returns the token if it was successfully consumed (consumed=false → consumed=true).
   * Returns null if the token was already consumed or does not exist.
   *
   * Implementation MUST use an atomic database operation:
   *   UPDATE enrollment_tokens SET consumed = true
   *   WHERE value = $1 AND consumed = false
   *   RETURNING *;
   *
   * This prevents the TOCTOU race where two concurrent requests both read
   * consumed=false and both write consumed=true — creating duplicate enrollments.
   */
  atomicConsume(value: string): Promise<EnrollmentToken | null>;
}
