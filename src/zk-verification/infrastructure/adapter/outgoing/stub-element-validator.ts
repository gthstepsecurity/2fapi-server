// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ElementValidator } from "../../../domain/port/outgoing/element-validator.js";

export interface StubElementValidatorConfig {
  readonly canonicalScalar?: boolean;
  readonly canonicalPoint?: boolean;
}

export class StubElementValidator implements ElementValidator {
  constructor(private readonly config: StubElementValidatorConfig = {}) {}

  isCanonicalScalar(): boolean {
    return this.config.canonicalScalar ?? true;
  }

  isCanonicalPoint(): boolean {
    return this.config.canonicalPoint ?? true;
  }
}
