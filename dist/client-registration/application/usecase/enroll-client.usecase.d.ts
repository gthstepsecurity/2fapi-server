import type { EnrollClient, EnrollClientRequest, EnrollClientResponse } from "../../domain/port/incoming/enroll-client.js";
import type { ClientRepository } from "../../domain/port/outgoing/client-repository.js";
import type { IdGenerator } from "../../domain/port/outgoing/id-generator.js";
import type { AuditLogger } from "../../domain/port/outgoing/audit-logger.js";
import type { EventPublisher } from "../../domain/port/outgoing/event-publisher.js";
import type { RateLimiter } from "../../domain/port/outgoing/rate-limiter.js";
import type { EnrollmentPolicy } from "../../domain/service/enrollment-policy.js";
export declare class EnrollClientUseCase implements EnrollClient {
    private readonly policy;
    private readonly repository;
    private readonly idGenerator;
    private readonly auditLogger;
    private readonly eventPublisher;
    private readonly rateLimiter?;
    constructor(policy: EnrollmentPolicy, repository: ClientRepository, idGenerator: IdGenerator, auditLogger: AuditLogger, eventPublisher: EventPublisher, rateLimiter?: RateLimiter | undefined);
    execute(request: EnrollClientRequest): Promise<EnrollClientResponse>;
}
//# sourceMappingURL=enroll-client.usecase.d.ts.map