export class TierDetector {
    localStore;
    biometricAvailable;
    constructor(localStore, biometricAvailable) {
        this.localStore = localStore;
        this.biometricAvailable = biometricAvailable;
    }
    async detect(email, deviceContext) {
        // Shared device → always Tier 0
        if (deviceContext.isShared) {
            return { tier: 0 };
        }
        // Check biometric (Tier 2)
        try {
            const hasBiometric = await this.biometricAvailable(email);
            if (hasBiometric) {
                return { tier: 2, credentialId: `bio-${email}` };
            }
        }
        catch {
            // Biometric check failed — fall through
        }
        // Check vault (Tier 1)
        if (this.localStore.exists(email)) {
            const entry = this.localStore.load(email);
            if (entry && !entry.isExpired(Date.now())) {
                return { tier: 1, deviceId: entry.deviceId };
            }
        }
        // Default: Tier 0
        return { tier: 0 };
    }
}
//# sourceMappingURL=tier-detector.js.map