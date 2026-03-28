// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
const EXPIRY_WARNING_HOURS = 12;
const STORAGE_KEY_PREFIX = "2fapi-vault:";

interface VaultEntryParams {
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly deviceId: string;
  readonly createdAtMs: number;
  readonly maxTtlHours: number;
  readonly version: number;
}

interface SerializedVaultEntry {
  readonly iv: string;
  readonly ciphertext: string;
  readonly tag: string;
  readonly deviceId: string;
  readonly createdAtMs: number;
  readonly maxTtlHours: number;
  readonly version: number;
}

/**
 * Value object representing an encrypted vault stored in localStorage.
 * Contains only the ciphertext and metadata — never the plaintext secret.
 */
export class VaultEntry {
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly tag: Uint8Array;
  readonly deviceId: string;
  readonly createdAtMs: number;
  readonly maxTtlHours: number;
  readonly version: number;

  private constructor(params: VaultEntryParams) {
    this.iv = params.iv;
    this.ciphertext = params.ciphertext;
    this.tag = params.tag;
    this.deviceId = params.deviceId;
    this.createdAtMs = params.createdAtMs;
    this.maxTtlHours = params.maxTtlHours;
    this.version = params.version;
  }

  static create(params: VaultEntryParams): VaultEntry {
    return new VaultEntry(params);
  }

  isExpired(nowMs: number): boolean {
    const expiresAtMs = this.createdAtMs + this.maxTtlHours * 60 * 60 * 1000;
    return nowMs >= expiresAtMs;
  }

  remainingHours(nowMs: number): number {
    const expiresAtMs = this.createdAtMs + this.maxTtlHours * 60 * 60 * 1000;
    const remainingMs = expiresAtMs - nowMs;
    return Math.max(0, Math.floor(remainingMs / (60 * 60 * 1000)));
  }

  isApproachingExpiry(nowMs: number): boolean {
    const remaining = this.remainingHours(nowMs);
    return remaining > 0 && remaining < EXPIRY_WARNING_HOURS;
  }

  storageKey(email: string): string {
    return `${STORAGE_KEY_PREFIX}${email}`;
  }

  serialize(): SerializedVaultEntry {
    return {
      iv: toBase64(this.iv),
      ciphertext: toBase64(this.ciphertext),
      tag: toBase64(this.tag),
      deviceId: this.deviceId,
      createdAtMs: this.createdAtMs,
      maxTtlHours: this.maxTtlHours,
      version: this.version,
    };
  }

  static deserialize(data: SerializedVaultEntry): VaultEntry {
    return new VaultEntry({
      iv: fromBase64(data.iv),
      ciphertext: fromBase64(data.ciphertext),
      tag: fromBase64(data.tag),
      deviceId: data.deviceId,
      createdAtMs: data.createdAtMs,
      maxTtlHours: data.maxTtlHours,
      version: data.version,
    });
  }
}

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function fromBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}
