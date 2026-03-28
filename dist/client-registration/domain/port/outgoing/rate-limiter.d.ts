export interface RateLimiter {
    isAllowed(clientIdentifier: string): Promise<boolean>;
}
//# sourceMappingURL=rate-limiter.d.ts.map