// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import type { ChallengeRepository } from "../../src/authentication-challenge/domain/port/outgoing/challenge-repository.js";
import type { NonceGenerator } from "../../src/authentication-challenge/domain/port/outgoing/nonce-generator.js";
import type { CredentialVerifier, CredentialVerificationResult } from "../../src/authentication-challenge/domain/port/outgoing/credential-verifier.js";
import type { ClientStatusChecker, LockoutInfo } from "../../src/authentication-challenge/domain/port/outgoing/client-status-checker.js";
import type { RateLimiter } from "../../src/authentication-challenge/domain/port/outgoing/rate-limiter.js";
import type { AuditLogger, AuditEntry } from "../../src/authentication-challenge/domain/port/outgoing/audit-logger.js";
import type { EventPublisher, DomainEvent } from "../../src/authentication-challenge/domain/port/outgoing/event-publisher.js";
import type { Clock } from "../../src/authentication-challenge/domain/port/outgoing/clock.js";
import type { IdGenerator } from "../../src/authentication-challenge/domain/port/outgoing/id-generator.js";
import type { Challenge } from "../../src/authentication-challenge/domain/model/challenge.js";
import type { ChallengeId } from "../../src/authentication-challenge/domain/model/challenge-id.js";
import { Nonce } from "../../src/authentication-challenge/domain/model/nonce.js";
import type { RequestChallengeRequest } from "../../src/authentication-challenge/application/dto/request-challenge.request.js";

export function createStubNonceGenerator(counter = { value: BigInt(0) }): NonceGenerator {
  return {
    generate(): Nonce {
      const random = new Uint8Array(16);
      globalThis.crypto.getRandomValues(random);
      const nonce = Nonce.create(random, counter.value);
      counter.value += BigInt(1);
      return nonce;
    },
  };
}

export function createStubCredentialVerifier(
  overrides: Partial<CredentialVerificationResult> = {},
): CredentialVerifier {
  return {
    async verify(): Promise<CredentialVerificationResult> {
      return {
        valid: overrides.valid ?? true,
        clientIdentifier: overrides.clientIdentifier ?? "alice",
        clientStatus: overrides.clientStatus ?? "active",
        isLegacyApiKey: overrides.isLegacyApiKey ?? false,
      };
    },
  };
}

export function createStubClientStatusChecker(
  overrides: Partial<LockoutInfo> = {},
): ClientStatusChecker & { failedAttempts: string[] } {
  const tracker = {
    failedAttempts: [] as string[],
    async getLockoutInfo(): Promise<LockoutInfo> {
      return {
        isLockedOut: overrides.isLockedOut ?? false,
        failedAttempts: overrides.failedAttempts ?? 0,
      };
    },
    async recordFailedAttempt(clientIdentifier: string): Promise<void> {
      tracker.failedAttempts.push(clientIdentifier);
    },
  };
  return tracker;
}

export function createStubRateLimiter(allowed = true): RateLimiter {
  return {
    async isAllowed(): Promise<boolean> {
      return allowed;
    },
  };
}

export function createCapturingAuditLogger(): AuditLogger & { entries: AuditEntry[] } {
  const logger = {
    entries: [] as AuditEntry[],
    async log(entry: AuditEntry): Promise<void> {
      logger.entries.push(entry);
    },
  };
  return logger;
}

export function createCapturingEventPublisher(): EventPublisher & { events: DomainEvent[] } {
  const publisher = {
    events: [] as DomainEvent[],
    async publish(event: DomainEvent): Promise<void> {
      publisher.events.push(event);
    },
  };
  return publisher;
}

export function createStubClock(nowMs = 1000000): Clock {
  return { nowMs: () => nowMs };
}

export function createStubIdGenerator(prefix = "ch"): IdGenerator {
  let counter = 0;
  return {
    generate(): string {
      counter++;
      return `${prefix}-${String(counter).padStart(3, "0")}`;
    },
  };
}

export function createInMemoryChallengeRepository(): ChallengeRepository & { challenges: Map<string, Challenge> } {
  const repo = {
    challenges: new Map<string, Challenge>(),
    async save(challenge: Challenge): Promise<void> {
      repo.challenges.set(challenge.id.value, challenge);
    },
    async findById(id: ChallengeId): Promise<Challenge | null> {
      return repo.challenges.get(id.value) ?? null;
    },
    async findPendingByClientIdentifier(clientIdentifier: string): Promise<Challenge | null> {
      for (const challenge of repo.challenges.values()) {
        if (challenge.clientIdentifier === clientIdentifier && challenge.status === "pending") {
          return challenge;
        }
      }
      return null;
    },
    async delete(id: ChallengeId): Promise<void> {
      repo.challenges.delete(id.value);
    },
    async deleteExpiredBefore(nowMs: number): Promise<number> {
      let count = 0;
      for (const [key, challenge] of repo.challenges.entries()) {
        if (!challenge.isValidAt(nowMs) && challenge.status !== "used") {
          repo.challenges.delete(key);
          count++;
        }
      }
      return count;
    },
    async capacityPercentage(): Promise<number> {
      return 0;
    },
  };
  return repo;
}

export function validChallengeRequest(
  identifier = "alice-payment-service",
): RequestChallengeRequest {
  return {
    clientIdentifier: identifier,
    credential: new Uint8Array(32).fill(0xaa),
    channelBinding: new Uint8Array(32).fill(0xcc),
    protocolVersion: "1.0",
  };
}
