// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { randomBytes } from "node:crypto";

const KEY_LENGTH = 32;

/**
 * Immutable value object representing a server-side OPRF key.
 * The key is a random 256-bit scalar used for blind evaluation.
 * Stored only on the server — never sent to the client.
 */
export class OprfKey {
  private constructor(
    readonly clientId: string,
    readonly deviceId: string,
    readonly value: Uint8Array,
    readonly isDestroyed: boolean,
  ) {}

  static generate(clientId: string, deviceId: string): OprfKey {
    const bytes = new Uint8Array(randomBytes(KEY_LENGTH));
    return new OprfKey(clientId, deviceId, bytes, false);
  }

  static restore(
    clientId: string,
    deviceId: string,
    value: Uint8Array,
    isDestroyed: boolean,
  ): OprfKey {
    return new OprfKey(clientId, deviceId, value, isDestroyed);
  }

  valueForEvaluation(): Uint8Array {
    if (this.isDestroyed) {
      throw new Error("OPRF key has been destroyed");
    }
    return this.value;
  }

  destroy(): OprfKey {
    const zeroed = new Uint8Array(KEY_LENGTH);
    return new OprfKey(this.clientId, this.deviceId, zeroed, true);
  }
}
