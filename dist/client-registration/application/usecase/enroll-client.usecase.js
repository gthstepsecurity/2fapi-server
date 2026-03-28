import { Client } from "../../domain/model/client.js";
import { Commitment } from "../../domain/model/commitment.js";
import { ClientEnrolled } from "../../domain/event/client-enrolled.js";
export class EnrollClientUseCase {
    policy;
    repository;
    idGenerator;
    auditLogger;
    eventPublisher;
    rateLimiter;
    constructor(policy, repository, idGenerator, auditLogger, eventPublisher, 
    // TODO: Replace optional rateLimiter with a NoopRateLimiter default (Null Object pattern)
    rateLimiter) {
        this.policy = policy;
        this.repository = repository;
        this.idGenerator = idGenerator;
        this.auditLogger = auditLogger;
        this.eventPublisher = eventPublisher;
        this.rateLimiter = rateLimiter;
    }
    async execute(request) {
        if (this.rateLimiter) {
            const allowed = await this.rateLimiter.isAllowed(request.clientIdentifier);
            if (!allowed) {
                await this.auditLogger.log({
                    eventType: "enrollment_failed",
                    timestamp: new Date(),
                    metadata: { reason: "RATE_LIMITED" },
                });
                return { success: false, error: "enrollment_failed" };
            }
        }
        // Issue #1 — Timing oracle mitigation: always execute ALL expensive operations
        // (validation, ID generation, commitment construction, client construction)
        // regardless of whether the client already exists, so that all code paths
        // have indistinguishable execution times.
        const validationError = this.policy.validate(request.commitmentBytes, request.proofOfPossession, request.clientIdentifier);
        const clientId = this.idGenerator.generate();
        let commitment = null;
        let client = null;
        try {
            commitment = Commitment.fromBytes(request.commitmentBytes);
            client = Client.register(clientId, request.clientIdentifier, commitment);
        }
        catch {
            // Construction may fail for invalid inputs; this is expected.
            // The actual error is reported via validationError below.
        }
        if (validationError || commitment === null || client === null) {
            await this.auditLogger.log({
                eventType: "enrollment_failed",
                timestamp: new Date(),
                metadata: { reason: validationError?.code ?? "INVALID_INPUT" },
            });
            return { success: false, error: "enrollment_failed" };
        }
        const existingClient = await this.repository.findByIdentifier(request.clientIdentifier);
        if (existingClient) {
            if (existingClient.commitment.equals(commitment)) {
                return {
                    success: true,
                    referenceId: existingClient.id.toString(),
                    clientIdentifier: existingClient.identifier,
                };
            }
            await this.auditLogger.log({
                eventType: "enrollment_failed",
                timestamp: new Date(),
                metadata: { reason: "DUPLICATE_IDENTIFIER" },
            });
            return { success: false, error: "enrollment_failed" };
        }
        try {
            await this.repository.save(client);
        }
        catch (error) {
            await this.auditLogger.log({
                eventType: "enrollment_failure",
                timestamp: new Date(),
                metadata: { reason: "SAVE_FAILED", error: error instanceof Error ? error.message : "unknown" },
            });
            return { success: false, error: "enrollment_failed" };
        }
        await this.eventPublisher.publish(new ClientEnrolled(request.clientIdentifier, clientId.toString()));
        await this.auditLogger.log({
            eventType: "enrollment_succeeded",
            clientIdentifier: request.clientIdentifier,
            timestamp: new Date(),
        });
        return {
            success: true,
            referenceId: clientId.toString(),
            clientIdentifier: request.clientIdentifier,
        };
    }
}
//# sourceMappingURL=enroll-client.usecase.js.map