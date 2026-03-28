// The commitment value is intentionally omitted from this event
// to prevent propagation of cryptographic material through the event bus.
export class ClientEnrolled {
    clientIdentifier;
    referenceId;
    eventType = "ClientEnrolled";
    occurredAt;
    constructor(clientIdentifier, referenceId) {
        this.clientIdentifier = clientIdentifier;
        this.referenceId = referenceId;
        this.occurredAt = new Date();
    }
}
//# sourceMappingURL=client-enrolled.js.map