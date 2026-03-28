// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type {
  CheckSuspensionStatus,
  CheckSuspensionStatusRequest,
  CheckSuspensionStatusResponse,
} from "../../domain/port/incoming/check-suspension-status.js";
import type { ClientStatusLookup } from "../../domain/port/outgoing/client-status-lookup.js";

/**
 * Checks whether a client is currently suspended.
 * Returns "active" for unknown or revoked clients (no information leakage).
 * Only returns "suspended" when the client is explicitly in suspended state.
 */
export class CheckSuspensionStatusUseCase implements CheckSuspensionStatus {
  constructor(
    private readonly clientStatusLookup: ClientStatusLookup,
  ) {}

  async execute(request: CheckSuspensionStatusRequest): Promise<CheckSuspensionStatusResponse> {
    const status = await this.clientStatusLookup.getStatus(request.clientIdentifier);

    if (status === "suspended") {
      return { status: "suspended" };
    }

    return { status: "active" };
  }
}
