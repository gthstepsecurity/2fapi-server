// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { GroupElement } from "./group-element.js";
import { ScalarValue } from "./scalar-value.js";

/** Total byte length of a serialized proof: 32 (A) + 32 (z_s) + 32 (z_r) */
export const PROOF_BYTE_LENGTH = 96;

export class Proof {
  private constructor(
    readonly announcement: GroupElement,
    readonly responseS: ScalarValue,
    readonly responseR: ScalarValue,
  ) {}

  static create(
    announcement: GroupElement,
    responseS: ScalarValue,
    responseR: ScalarValue,
  ): Proof {
    if (announcement.isIdentity()) {
      throw new Error("Announcement must not be the identity element");
    }
    return new Proof(announcement, responseS, responseR);
  }

  static fromBytes(bytes: Uint8Array): Proof {
    if (bytes.length !== PROOF_BYTE_LENGTH) {
      throw new Error(`Proof must be exactly ${PROOF_BYTE_LENGTH} bytes, got ${bytes.length}`);
    }
    const announcement = GroupElement.fromBytes(bytes.slice(0, 32));
    const responseS = ScalarValue.fromBytes(bytes.slice(32, 64));
    const responseR = ScalarValue.fromBytes(bytes.slice(64, 96));
    return Proof.create(announcement, responseS, responseR);
  }

  toBytes(): Uint8Array {
    const bytes = new Uint8Array(PROOF_BYTE_LENGTH);
    bytes.set(this.announcement.toBytes(), 0);
    bytes.set(this.responseS.toBytes(), 32);
    bytes.set(this.responseR.toBytes(), 64);
    return bytes;
  }
}
