// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { Client } from "../../../../src/client-registration/domain/model/client.js";
import { ClientId } from "../../../../src/client-registration/domain/model/client-id.js";
import { Commitment } from "../../../../src/client-registration/domain/model/commitment.js";

function validCommitmentBytes(): Uint8Array {
  const bytes = new Uint8Array(32);
  bytes[0] = 0xab;
  bytes[1] = 0xcd;
  return bytes;
}

function validClientId(): ClientId {
  return ClientId.fromBytes(new Uint8Array(16).fill(7));
}

describe("Client", () => {
  it("is created with id, identifier, commitment and status active", () => {
    const id = validClientId();
    const commitment = Commitment.fromBytes(validCommitmentBytes());
    const client = Client.register(id, "alice-payment-service", commitment);

    expect(client.id.equals(id)).toBe(true);
    expect(client.identifier).toBe("alice-payment-service");
    expect(client.commitment.equals(commitment)).toBe(true);
    expect(client.status).toBe("active");
  });

  it("exposes the commitment bytes exactly as provided", () => {
    const bytes = validCommitmentBytes();
    const commitment = Commitment.fromBytes(bytes);
    const client = Client.register(validClientId(), "svc", commitment);
    expect(client.commitment.toBytes()).toEqual(bytes);
  });

  it("rejects empty identifier", () => {
    const id = validClientId();
    const commitment = Commitment.fromBytes(validCommitmentBytes());
    expect(() => Client.register(id, "", commitment)).toThrow(
      "identifier must not be empty",
    );
  });

  it("rejects whitespace-only identifier", () => {
    // Kill mutant: `!identifier && identifier.trim().length === 0` instead of `||`
    // and: `!identifier || false` instead of checking trim
    // and: `identifier.length === 0` instead of `identifier.trim().length === 0`
    const id = validClientId();
    const commitment = Commitment.fromBytes(validCommitmentBytes());
    expect(() => Client.register(id, "   ", commitment)).toThrow(
      "identifier must not be empty",
    );
  });

  describe("revoke", () => {
    it("returns a new client with status revoked", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);

      const revoked = client.revoke();

      expect(revoked.status).toBe("revoked");
      expect(revoked.id.equals(client.id)).toBe(true);
      expect(revoked.identifier).toBe(client.identifier);
      expect(revoked.commitment.equals(client.commitment)).toBe(true);
    });

    it("is idempotent — revoking an already revoked client returns same instance (BA01)", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);

      const revoked = client.revoke();
      const revokedAgain = revoked.revoke();

      expect(revokedAgain.status).toBe("revoked");
      // BA01: Returns the same instance without mutation
      expect(revokedAgain).toBe(revoked);
    });
  });

  describe("rotateCommitment", () => {
    it("returns a new client with the new commitment", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const newBytes = new Uint8Array(32).fill(0xee);
      const newCommitment = Commitment.fromBytes(newBytes);

      const rotated = client.rotateCommitment(newCommitment);

      expect(rotated.commitment.equals(newCommitment)).toBe(true);
      expect(rotated.status).toBe("active");
      expect(rotated.id.equals(client.id)).toBe(true);
      expect(rotated.identifier).toBe(client.identifier);
    });

    it("increments commitmentVersion on each rotation", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      expect(client.commitmentVersion).toBe(1);

      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));
      const rotated = client.rotateCommitment(newCommitment);
      expect(rotated.commitmentVersion).toBe(2);

      const nextCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xff));
      const rotatedAgain = rotated.rotateCommitment(nextCommitment);
      expect(rotatedAgain.commitmentVersion).toBe(3);
    });

    it("rejects rotation when client is revoked", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const revoked = client.revoke();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));

      expect(() => revoked.rotateCommitment(newCommitment)).toThrow(
        "Cannot rotate commitment for a non-active client",
      );
    });

    it("rejects rotation when client is suspended", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const suspended = client.suspend();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));

      expect(() => suspended.rotateCommitment(newCommitment)).toThrow(
        "Cannot rotate commitment for a non-active client",
      );
    });
  });

  describe("reactivate", () => {
    it("returns a new client with status active and new commitment when suspended", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const suspended = client.suspend();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));

      const reactivated = suspended.reactivate(newCommitment);

      expect(reactivated.status).toBe("active");
      expect(reactivated.commitment.equals(newCommitment)).toBe(true);
      expect(reactivated.id.equals(client.id)).toBe(true);
      expect(reactivated.identifier).toBe(client.identifier);
    });

    it("increments commitmentVersion on reactivation", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      expect(client.commitmentVersion).toBe(1);

      const suspended = client.suspend();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));
      const reactivated = suspended.reactivate(newCommitment);
      expect(reactivated.commitmentVersion).toBe(2);
    });

    it("rejects reactivation when client is active", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));

      expect(() => client.reactivate(newCommitment)).toThrow(
        "Cannot reactivate a client that is not suspended",
      );
    });

    it("rejects reactivation when client is revoked", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const revoked = client.revoke();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));

      expect(() => revoked.reactivate(newCommitment)).toThrow(
        "Cannot reactivate a client that is not suspended",
      );
    });

    it("preserves identifier through suspend-reactivate cycle", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "alice-payment-service", commitment);
      const suspended = client.suspend();
      const newCommitment = Commitment.fromBytes(new Uint8Array(32).fill(0xee));
      const reactivated = suspended.reactivate(newCommitment);

      expect(reactivated.identifier).toBe("alice-payment-service");
    });
  });

  describe("suspend", () => {
    it("returns a new client with status suspended", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);

      const suspended = client.suspend();

      expect(suspended.status).toBe("suspended");
      expect(suspended.id.equals(client.id)).toBe(true);
      expect(suspended.identifier).toBe(client.identifier);
      expect(suspended.commitment.equals(client.commitment)).toBe(true);
      expect(suspended.commitmentVersion).toBe(client.commitmentVersion);
    });

    it("is idempotent — suspending an already suspended client returns suspended", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);

      const suspended = client.suspend();
      const suspendedAgain = suspended.suspend();

      expect(suspendedAgain.status).toBe("suspended");
    });

    it("rejects suspending a revoked client", () => {
      const commitment = Commitment.fromBytes(validCommitmentBytes());
      const client = Client.register(validClientId(), "svc", commitment);
      const revoked = client.revoke();

      expect(() => revoked.suspend()).toThrow(
        "Cannot suspend a revoked client",
      );
    });
  });
});
