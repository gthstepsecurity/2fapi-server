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
export declare class DeviceContextDetector {
    /**
     * Detect device context from tenant policy and local signals.
     */
    detect(params: DetectionParams): DeviceContext;
}
export interface DetectionParams {
    readonly tenantPolicy?: "shared_enforced" | "personal_enforced" | "ask_user";
    readonly userDeclaredMode?: DeviceMode;
    readonly isKioskMode?: boolean;
    readonly isRemoteDesktop?: boolean;
    readonly hasMultipleAccounts?: boolean;
    readonly localStorageUnavailable?: boolean;
}
//# sourceMappingURL=device-context-detector.d.ts.map
