// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
// Shared error types for the enrollment bounded context.
// If additional bounded contexts are added, evaluate whether
// error types should be context-specific rather than shared.

export class EnrollmentError extends Error {
  constructor(
    readonly code: EnrollmentErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "EnrollmentError";
  }
}

export type EnrollmentErrorCode =
  | "MISSING_COMMITMENT"
  | "INVALID_ENCODING"
  | "INVALID_GROUP_ELEMENT"
  | "IDENTITY_ELEMENT"
  | "MISSING_PROOF"
  | "INVALID_PROOF"
  | "DUPLICATE_IDENTIFIER"
  | "RATE_LIMITED"
  | "CAPACITY_EXCEEDED";

export class LifecycleError extends Error {
  constructor(
    readonly code: LifecycleErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "LifecycleError";
  }
}

export type LifecycleErrorCode =
  | "MISSING_ADMIN_IDENTITY"
  | "CLIENT_NOT_ACTIVE"
  | "SAME_COMMITMENT"
  | "IDENTITY_ELEMENT"
  | "INVALID_ENCODING"
  | "INVALID_CURRENT_PROOF"
  | "INVALID_NEW_PROOF"
  | "RATE_LIMITED";
