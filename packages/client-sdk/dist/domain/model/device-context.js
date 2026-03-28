export class DeviceContext {
    mode;
    detectionMethod;
    constructor(mode, detectionMethod) {
        this.mode = mode;
        this.detectionMethod = detectionMethod;
    }
    static personal(method = "user_declared") {
        return new DeviceContext("personal", method);
    }
    static shared(method = "user_declared") {
        return new DeviceContext("shared", method);
    }
    static kiosk() {
        return new DeviceContext("kiosk", "auto_detected");
    }
    get isShared() {
        return this.mode === "shared" || this.mode === "kiosk";
    }
    get isPersonal() {
        return this.mode === "personal";
    }
    get allowsPersistence() {
        return this.isPersonal;
    }
    get allowsBiometric() {
        return this.isPersonal;
    }
    get allowsVault() {
        return this.isPersonal;
    }
}
//# sourceMappingURL=device-context.js.map