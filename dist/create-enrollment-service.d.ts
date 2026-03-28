import type { ClientRepository } from "./client-registration/domain/port/outgoing/client-repository.js";
import type { CommitmentVerifier } from "./client-registration/domain/port/outgoing/commitment-verifier.js";
import type { ProofOfPossessionVerifier } from "./client-registration/domain/port/outgoing/proof-of-possession-verifier.js";
import type { IdGenerator } from "./client-registration/domain/port/outgoing/id-generator.js";
import type { AuditLogger } from "./client-registration/domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "./client-registration/domain/port/outgoing/event-publisher.js";
import type { RateLimiter } from "./client-registration/domain/port/outgoing/rate-limiter.js";
import type { EnrollClient } from "./client-registration/domain/port/incoming/enroll-client.js";
export interface EnrollmentServiceDependencies {
    clientRepository: ClientRepository;
    commitmentVerifier: CommitmentVerifier;
    proofOfPossessionVerifier: ProofOfPossessionVerifier;
    idGenerator: IdGenerator;
    auditLogger: AuditLogger;
    eventPublisher: EventPublisher;
    rateLimiter?: RateLimiter;
}
export declare function createEnrollmentService(deps: EnrollmentServiceDependencies): EnrollClient;
//# sourceMappingURL=create-enrollment-service.d.ts.map