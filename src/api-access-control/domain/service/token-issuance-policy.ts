// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
export type IssuancePolicyErrorCode =
  | "CLIENT_NOT_ACTIVE"
  | "CLIENT_NOT_AUTHORIZED";

export class IssuancePolicyError extends Error {
  constructor(
    readonly code: IssuancePolicyErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "IssuancePolicyError";
  }
}

export interface IssuancePreconditions {
  readonly clientActive: boolean;
  readonly clientAuthorized: boolean;
}

export class TokenIssuancePolicy {
  validate(preconditions: IssuancePreconditions): IssuancePolicyError | null {
    if (!preconditions.clientActive) {
      return new IssuancePolicyError(
        "CLIENT_NOT_ACTIVE",
        "Client is not active",
      );
    }

    if (!preconditions.clientAuthorized) {
      return new IssuancePolicyError(
        "CLIENT_NOT_AUTHORIZED",
        "Client is not authorized for the requested audience",
      );
    }

    return null;
  }
}
