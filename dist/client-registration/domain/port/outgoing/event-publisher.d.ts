export interface DomainEvent {
    readonly eventType: string;
    readonly occurredAt: Date;
}
export interface EventPublisher {
    publish(event: DomainEvent): Promise<void>;
}
//# sourceMappingURL=event-publisher.d.ts.map