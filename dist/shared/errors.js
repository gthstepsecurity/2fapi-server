// Shared error types for the enrollment bounded context.
// If additional bounded contexts are added, evaluate whether
// error types should be context-specific rather than shared.
export class EnrollmentError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
        this.name = "EnrollmentError";
    }
}
//# sourceMappingURL=errors.js.map