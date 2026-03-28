import type { DomainEvent } from "../port/outgoing/event-publisher.js";
export declare class ClientEnrolled implements DomainEvent {
    readonly clientIdentifier: string;
    readonly referenceId: string;
    readonly eventType = "ClientEnrolled";
    readonly occurredAt: Date;
    constructor(clientIdentifier: string, referenceId: string);
}
//# sourceMappingURL=client-enrolled.d.ts.map