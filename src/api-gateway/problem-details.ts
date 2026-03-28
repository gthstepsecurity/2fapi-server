// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * RFC 7807 Problem Details for HTTP APIs.
 * Provides a consistent error response format across all endpoints.
 */
export interface ProblemDetails {
  readonly type: string;
  readonly title: string;
  readonly status: number;
  readonly detail: string;
  readonly instance: string;
  readonly [key: string]: unknown;
}

export function createProblemDetails(
  type: string,
  title: string,
  status: number,
  detail: string,
  instance: string,
  extensions?: Record<string, unknown>,
): ProblemDetails {
  return {
    type,
    title,
    status,
    detail,
    instance,
    ...extensions,
  };
}
