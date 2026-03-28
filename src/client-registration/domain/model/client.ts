// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ClientId } from "./client-id.js";
import type { ClientStatus } from "./client-status.js";
import type { Commitment } from "./commitment.js";

export class Client {
  readonly id: ClientId;
  readonly identifier: string;
  readonly commitment: Commitment;
  readonly status: ClientStatus;
  readonly commitmentVersion: number;

  private constructor(
    id: ClientId,
    identifier: string,
    commitment: Commitment,
    status: ClientStatus,
    commitmentVersion: number,
  ) {
    this.id = id;
    this.identifier = identifier;
    this.commitment = commitment;
    this.status = status;
    this.commitmentVersion = commitmentVersion;
  }

  static register(
    id: ClientId,
    identifier: string,
    commitment: Commitment,
  ): Client {
    if (!identifier || identifier.trim().length === 0) {
      throw new Error("Client identifier must not be empty");
    }
    return new Client(id, identifier, commitment, "active", 1);
  }

  /**
   * Reconstitutes a Client from persisted data.
   * Bypasses business validation since the data comes from a trusted store.
   */
  static reconstitute(
    id: ClientId,
    identifier: string,
    commitment: Commitment,
    status: ClientStatus,
    commitmentVersion: number,
  ): Client {
    return new Client(id, identifier, commitment, status, commitmentVersion);
  }

  revoke(): Client {
    // BA01: Idempotent — if already revoked, return same state without mutation
    if (this.status === "revoked") {
      return this;
    }
    return new Client(this.id, this.identifier, this.commitment, "revoked", this.commitmentVersion);
  }

  suspend(): Client {
    if (this.status === "revoked") {
      throw new Error("Cannot suspend a revoked client");
    }
    return new Client(this.id, this.identifier, this.commitment, "suspended", this.commitmentVersion);
  }

  rotateCommitment(newCommitment: Commitment): Client {
    if (this.status !== "active") {
      throw new Error("Cannot rotate commitment for a non-active client");
    }
    return new Client(this.id, this.identifier, newCommitment, "active", this.commitmentVersion + 1);
  }

  reactivate(newCommitment: Commitment): Client {
    if (this.status !== "suspended") {
      throw new Error("Cannot reactivate a client that is not suspended");
    }
    return new Client(this.id, this.identifier, newCommitment, "active", this.commitmentVersion + 1);
  }
}
