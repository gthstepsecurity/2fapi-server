// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { LifecycleError } from "../../../shared/errors.js";

export class RevocationPolicy {
  validate(adminIdentity: string): LifecycleError | null {
    if (!adminIdentity || adminIdentity.trim().length === 0) {
      return new LifecycleError("MISSING_ADMIN_IDENTITY", "Admin identity is required for revocation");
    }
    return null;
  }
}
