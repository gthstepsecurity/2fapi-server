// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { SuspensionReasonValue } from "../../model/suspension-reason.js";

/**
 * Anti-corruption layer port to the Client Registration bounded context.
 * Suspends a client by its identifier. Returns true if the suspension was applied,
 * false if the client was already suspended or revoked.
 */
export interface ClientSuspender {
  suspend(clientIdentifier: string, reason: SuspensionReasonValue): Promise<boolean>;
}
