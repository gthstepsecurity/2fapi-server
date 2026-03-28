export declare class EnrollmentError extends Error {
    readonly code: EnrollmentErrorCode;
    constructor(code: EnrollmentErrorCode, message: string);
}
export type EnrollmentErrorCode = "MISSING_COMMITMENT" | "INVALID_ENCODING" | "INVALID_GROUP_ELEMENT" | "IDENTITY_ELEMENT" | "MISSING_PROOF" | "INVALID_PROOF" | "DUPLICATE_IDENTIFIER" | "RATE_LIMITED" | "CAPACITY_EXCEEDED";
//# sourceMappingURL=errors.d.ts.map