// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ElementValidator } from "../../../domain/port/outgoing/element-validator.js";

/**
 * Contract for the native crypto module used by the element validator.
 */
export interface NativeElementValidationModule {
  isCanonicalScalar(bytes: Buffer): boolean;
  isCanonicalPoint(bytes: Buffer): boolean;
}

/**
 * Real implementation of ElementValidator using the Rust crypto core
 * via @2fapi/crypto-native napi-rs bindings.
 *
 * Validates canonical encoding of Ristretto255 points and scalars.
 */
export class NapiElementValidator implements ElementValidator {
  constructor(private readonly nativeModule: NativeElementValidationModule) {}

  isCanonicalScalar(bytes: Uint8Array): boolean {
    try {
      return this.nativeModule.isCanonicalScalar(Buffer.from(bytes));
    } catch {
      // Native errors are treated as invalid encoding.
      return false;
    }
  }

  isCanonicalPoint(bytes: Uint8Array): boolean {
    try {
      return this.nativeModule.isCanonicalPoint(Buffer.from(bytes));
    } catch {
      // Native errors are treated as invalid encoding.
      return false;
    }
  }
}
