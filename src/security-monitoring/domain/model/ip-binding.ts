// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Value object representing an IP address binding to a client.
 * Records which IP a client was using at a given point in time.
 * Immutable — frozen at creation.
 */
export class IpBinding {
  readonly clientIdentifier: string;
  readonly sourceIp: string;
  readonly boundAtMs: number;

  private constructor(clientIdentifier: string, sourceIp: string, boundAtMs: number) {
    this.clientIdentifier = clientIdentifier;
    this.sourceIp = sourceIp;
    this.boundAtMs = boundAtMs;
    Object.freeze(this);
  }

  static create(clientIdentifier: string, sourceIp: string, boundAtMs: number): IpBinding {
    if (!clientIdentifier || clientIdentifier.trim().length === 0) {
      throw new Error("Client identifier must not be empty");
    }
    if (!sourceIp || sourceIp.trim().length === 0) {
      throw new Error("Source IP must not be empty");
    }
    if (boundAtMs < 0) {
      throw new Error("Bound timestamp must be non-negative");
    }
    return new IpBinding(clientIdentifier, sourceIp, boundAtMs);
  }

  equals(other: IpBinding): boolean {
    return (
      this.clientIdentifier === other.clientIdentifier &&
      this.sourceIp === other.sourceIp &&
      this.boundAtMs === other.boundAtMs
    );
  }
}
