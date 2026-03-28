// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "./result.js";

const MIN_LENGTH = 8;

/**
 * Value object representing a device password used to seal/unseal the vault.
 * Distinct from the 2FApi passphrase/PIN — this protects local storage only.
 */
export class DevicePassword {
  private constructor(readonly value: string) {}

  static create(raw: string): Result<DevicePassword, string> {
    if (raw.length < MIN_LENGTH) {
      return err("Password must be at least 8 characters");
    }
    return ok(new DevicePassword(raw));
  }

  matches(confirmation: string): boolean {
    return this.value === confirmation;
  }
}
