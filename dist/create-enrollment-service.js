// Composition root: assembles all dependencies for the enrollment service.
// Lives at src/ root as the library's primary entry point for consumers.
// Alternative location: client-registration/infrastructure/config/
import { EnrollmentPolicy } from "./client-registration/domain/service/enrollment-policy.js";
import { EnrollClientUseCase } from "./client-registration/application/usecase/enroll-client.usecase.js";
export function createEnrollmentService(deps) {
    const policy = new EnrollmentPolicy(deps.commitmentVerifier, deps.proofOfPossessionVerifier);
    return new EnrollClientUseCase(policy, deps.clientRepository, deps.idGenerator, deps.auditLogger, deps.eventPublisher, deps.rateLimiter);
}
//# sourceMappingURL=create-enrollment-service.js.map