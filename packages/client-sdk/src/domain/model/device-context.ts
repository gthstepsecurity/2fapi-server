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

export class DeviceContext {
  private constructor(
    readonly mode: DeviceMode,
    readonly detectionMethod: DetectionMethod,
  ) {}

  static personal(method: DetectionMethod = "user_declared"): DeviceContext {
    return new DeviceContext("personal", method);
  }

  static shared(method: DetectionMethod = "user_declared"): DeviceContext {
    return new DeviceContext("shared", method);
  }

  static kiosk(): DeviceContext {
    return new DeviceContext("kiosk", "auto_detected");
  }

  get isShared(): boolean {
    return this.mode === "shared" || this.mode === "kiosk";
  }

  get isPersonal(): boolean {
    return this.mode === "personal";
  }

  get allowsPersistence(): boolean {
    return this.isPersonal;
  }

  get allowsBiometric(): boolean {
    return this.isPersonal;
  }

  get allowsVault(): boolean {
    return this.isPersonal;
  }
}
