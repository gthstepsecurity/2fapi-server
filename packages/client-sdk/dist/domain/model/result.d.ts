// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
/**
 * Lightweight Result type for domain error handling.
 * No external dependencies — pure domain code.
 */
export interface Ok<T> {
    readonly kind: "ok";
    readonly value: T;
    isOk(): boolean;
    isErr(): boolean;
    unwrap(): T;
    unwrapErr(): never;
}
export interface Err<E> {
    readonly kind: "err";
    readonly error: E;
    isOk(): boolean;
    isErr(): boolean;
    unwrap(): never;
    unwrapErr(): E;
}
export type Result<T, E> = Ok<T> | Err<E>;
export declare function ok<T>(value: T): Ok<T>;
export declare function err<E>(error: E): Err<E>;
//# sourceMappingURL=result.d.ts.map
