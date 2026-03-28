// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object representing the device context for storage tier selection.
 *
 * Determines whether the device is personal (Tier 1/2) or shared (Tier 0).
 * On a shared device, NOTHING is persisted — no localStorage, no Credential Manager.
 */
export type DeviceMode = "personal" | "shared" | "kiosk";
export type DetectionMethod = "admin_enforced" | "user_declared" | "auto_detected";
export declare class DeviceContext {
    readonly mode: DeviceMode;
    readonly detectionMethod: DetectionMethod;
    private constructor();
    static personal(method?: DetectionMethod): DeviceContext;
    static shared(method?: DetectionMethod): DeviceContext;
    static kiosk(): DeviceContext;
    get isShared(): boolean;
    get isPersonal(): boolean;
    get allowsPersistence(): boolean;
    get allowsBiometric(): boolean;
    get allowsVault(): boolean;
}
//# sourceMappingURL=device-context.d.ts.map
