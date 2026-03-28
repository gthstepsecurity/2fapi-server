// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Outgoing port for storing and retrieving recovery key hashes.
 * The domain stores Argon2id hashes of recovery phrases;
 * the actual storage mechanism is an infrastructure concern.
 */
export interface RecoveryHashStore {
  /** Stores the Argon2id hash of the recovery key for a client */
  storeHash(clientIdentifier: string, hash: Uint8Array): Promise<void>;

  /** Retrieves the stored hash for a client, or null if none exists */
  getHash(clientIdentifier: string): Promise<Uint8Array | null>;

  /** Records a failed recovery attempt and returns the updated count */
  recordFailedAttempt(clientIdentifier: string): Promise<number>;

  /** Resets the failed attempt counter for a client (on successful recovery) */
  resetAttempts(clientIdentifier: string): Promise<void>;

  /** Returns the current failed attempt count for a client (0 if no attempts recorded) */
  getAttemptCount(clientIdentifier: string): Promise<number>;

  /** Deletes the stored hash for a client (used on external reactivation to invalidate old phrase) */
  deleteHash(clientIdentifier: string): Promise<void>;
}
