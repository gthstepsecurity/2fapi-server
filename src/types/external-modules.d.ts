// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Type declarations for external modules that may not be installed.
 *
 * These declarations allow TypeScript to compile without the actual
 * packages being installed. The packages must be installed at runtime.
 */

declare module "pg" {
  export interface PoolConfig {
    host?: string;
    port?: number;
    database?: string;
    user?: string;
    password?: string;
    ssl?: { rejectUnauthorized: boolean } | boolean;
  }

  export interface QueryResult {
    rows: any[];
    rowCount: number | null;
  }

  export interface PoolClient {
    query(text: string, values?: unknown[]): Promise<QueryResult>;
    release(): void;
  }

  export class Pool {
    constructor(config?: PoolConfig);
    connect(): Promise<PoolClient>;
    query(text: string, values?: unknown[]): Promise<QueryResult>;
    end(): Promise<void>;
  }
}

declare module "ioredis" {
  interface RedisOptions {
    host?: string;
    port?: number;
    password?: string;
    tls?: object;
  }

  class Redis {
    constructor(options?: RedisOptions);
    get(key: string): Promise<string | null>;
    set(key: string, value: string, ...args: string[]): Promise<string | null>;
    del(...keys: string[]): Promise<number>;
    keys(pattern: string): Promise<string[]>;
    ttl(key: string): Promise<number>;
    dbsize(): Promise<number>;
    incr(key: string): Promise<number>;
    expire(key: string, seconds: number): Promise<number>;
    ping(): Promise<string>;
    quit(): Promise<string>;
    flushdb(): Promise<string>;
    multi(): Redis.Pipeline;
  }

  namespace Redis {
    interface Pipeline {
      zremrangebyscore(key: string, min: string | number, max: string | number): Pipeline;
      zadd(key: string, ...args: (string | number)[]): Pipeline;
      zcard(key: string): Pipeline;
      expire(key: string, seconds: number): Pipeline;
      exec(): Promise<unknown[]>;
    }
  }

  export default Redis;
}

declare module "@noble/ed25519" {
  export function signAsync(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  export function verifyAsync(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
  export function getPublicKeyAsync(privateKey: Uint8Array): Promise<Uint8Array>;
  export const utils: {
    randomPrivateKey(): Uint8Array;
  };
}

declare module "argon2" {
  interface Options {
    type: number;
    salt: Buffer;
    memoryCost: number;
    timeCost: number;
    parallelism: number;
    hashLength: number;
    raw: boolean;
  }

  export function hash(password: Buffer, options: Options): Promise<Buffer>;
  export const argon2id: number;

  const argon2: {
    hash: typeof hash;
    argon2id: typeof argon2id;
  };

  export default argon2;
}
