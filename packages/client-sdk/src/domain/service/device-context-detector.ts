// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { DeviceContext, type DeviceMode } from "../model/device-context.js";

/**
 * Domain service: detects whether the current device is personal or shared.
 *
 * Detection hierarchy (highest priority first):
 * 1. Admin tenant policy (enforced — cannot be overridden)
 * 2. User declaration (stored in localStorage as the only allowed flag)
 * 3. Auto-detection heuristics (kiosk mode, remote desktop, multiple accounts)
 */
export class DeviceContextDetector {
  /**
   * Detect device context from tenant policy and local signals.
   */
  detect(params: DetectionParams): DeviceContext {
    // 1. Admin-enforced policy takes precedence
    if (params.tenantPolicy === "shared_enforced") {
      return DeviceContext.shared("admin_enforced");
    }
    if (params.tenantPolicy === "personal_enforced") {
      return DeviceContext.personal("admin_enforced");
    }

    // 2. User's previous declaration (if stored)
    if (params.userDeclaredMode !== undefined) {
      return params.userDeclaredMode === "shared"
        ? DeviceContext.shared("user_declared")
        : DeviceContext.personal("user_declared");
    }

    // 3. Auto-detection heuristics
    if (params.isKioskMode) {
      return DeviceContext.kiosk();
    }
    if (params.isRemoteDesktop) {
      return DeviceContext.shared("auto_detected");
    }
    if (params.hasMultipleAccounts) {
      return DeviceContext.shared("auto_detected");
    }
    if (params.localStorageUnavailable) {
      return DeviceContext.shared("auto_detected");
    }

    // 4. Default: ask the user (return undefined to signal "ask")
    // For now, default to personal (the caller should prompt)
    return DeviceContext.personal("user_declared");
  }
}

export interface DetectionParams {
  readonly tenantPolicy?: "shared_enforced" | "personal_enforced" | "ask_user";
  readonly userDeclaredMode?: DeviceMode;
  readonly isKioskMode?: boolean;
  readonly isRemoteDesktop?: boolean;
  readonly hasMultipleAccounts?: boolean;
  readonly localStorageUnavailable?: boolean;
}
