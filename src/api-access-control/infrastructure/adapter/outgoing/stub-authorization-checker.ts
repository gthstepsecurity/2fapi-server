// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { AuthorizationChecker } from "../../../domain/port/outgoing/authorization-checker.js";

export class StubAuthorizationChecker implements AuthorizationChecker {
  checkCalls: Array<{ clientIdentifier: string; audience: string }> = [];

  constructor(private authorized: boolean = true) {}

  async isAuthorized(clientIdentifier: string, audience: string): Promise<boolean> {
    this.checkCalls.push({ clientIdentifier, audience });
    return this.authorized;
  }

  setAuthorized(authorized: boolean): void {
    this.authorized = authorized;
  }
}
