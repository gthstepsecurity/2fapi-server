/**
 * Infrastructure adapter: communicates with the 2FApi server for vault operations.
 * Handles pepper delivery, attempt counter, and lifecycle notifications.
 */
export class HttpVaultServerGateway {
    baseUrl;
    fetch;
    constructor(baseUrl, fetch) {
        this.baseUrl = baseUrl;
        this.fetch = fetch;
    }
    async requestSeal(params) {
        const response = await this.post("/v1/vault/seal", {
            client_id: params.clientId,
            device_id: params.deviceId,
        });
        const body = await response.json();
        return {
            pepper: fromBase64(body.pepper),
            deviceId: body.device_id,
        };
    }
    async requestUnseal(params) {
        const response = await this.post("/v1/vault/unseal-attempt", {
            client_id: params.clientId,
            device_id: params.deviceId,
        });
        const body = await response.json();
        if (body.status === "wiped") {
            return { status: "wiped" };
        }
        if (body.status === "vault_expired") {
            return { status: "vault_expired" };
        }
        return {
            status: "allowed",
            pepper: fromBase64(body.pepper),
            attemptsRemaining: body.attempts_remaining,
        };
    }
    async reportUnsealFailure(params) {
        await this.post("/v1/vault/unseal-failed", {
            client_id: params.clientId,
            device_id: params.deviceId,
        });
    }
    async reportAuthSuccess(params) {
        await this.post("/v1/vault/auth-success", {
            client_id: params.clientId,
            device_id: params.deviceId,
        });
    }
    async deleteVaultRegistration(clientId, deviceId) {
        await this.post("/v1/vault/delete", {
            client_id: clientId,
            device_id: deviceId,
        });
    }
    async post(path, body) {
        const url = `${this.baseUrl}${path}`;
        const response = await this.fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }
        return response;
    }
}
function fromBase64(str) {
    // Works in both Node.js (Buffer) and browser (atob)
    if (typeof Buffer !== "undefined") {
        return new Uint8Array(Buffer.from(str, "base64"));
    }
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
//# sourceMappingURL=http-vault-server-gateway.js.map