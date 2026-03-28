/**
 * Lightweight Result type for domain error handling.
 * No external dependencies — pure domain code.
 */
export function ok(value) {
    return {
        kind: "ok",
        value,
        isOk: () => true,
        isErr: () => false,
        unwrap: () => value,
        unwrapErr: () => {
            throw new Error("Called unwrapErr on Ok");
        },
    };
}
export function err(error) {
    return {
        kind: "err",
        error,
        isOk: () => false,
        isErr: () => true,
        unwrap: () => {
            throw new Error(`Called unwrap on Err: ${String(error)}`);
        },
        unwrapErr: () => error,
    };
}
//# sourceMappingURL=result.js.map