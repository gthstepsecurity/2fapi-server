import type { EventPublisher, DomainEvent } from "../../../domain/port/outgoing/event-publisher.js";
export declare class NoopEventPublisher implements EventPublisher {
    publish(_event: DomainEvent): Promise<void>;
}
//# sourceMappingURL=noop-event-publisher.d.ts.map