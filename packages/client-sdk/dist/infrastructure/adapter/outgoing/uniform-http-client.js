import { randomBytes } from "node:crypto";
/**
 * Infrastructure adapter: sends ALL vault requests through a single endpoint
 * with fixed-size enveloped bodies (R23-01, R23-02, R23-04 fix).
 *
 * Every request:
 *   POST /v1/vault
 *   Authorization: Bearer <token or dummy, fixed length>
 *   Body: { data: "<960 hex chars>" }
 *
 * The operation type (seal, evaluate, unseal-result, dummy) is INSIDE
 * the encrypted envelope. An observer sees identical requests.
 */
const ENVELOPE_PLAINTEXT_SIZE = 480;
const DUMMY_TOKEN_LENGTH = 256; // fixed JWT-like length
export class UniformHttpClient {
    baseUrl;
    fetch;
    constructor(baseUrl, fetch) {
        this.baseUrl = baseUrl;
        this.fetch = fetch;
    }
    /**
     * Send a vault operation through the single uniform endpoint.
     * All requests have identical external characteristics.
     */
    async send(operation, authToken) {
        const body = envelopeRequest(operation);
        const token = authToken ?? generateDummyToken();
        const response = await this.fetch(`${this.baseUrl}/v1/vault`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${padToken(token)}`,
            },
            body: JSON.stringify(body),
        });
        const responseBody = await response.json();
        return parseEnvelope(responseBody.data);
    }
    /**
     * Send a dummy request (for request count normalization).
     * Identical to a real request from the outside.
     */
    async sendDummy() {
        await this.send({ op: "dummy" });
    }
}
// --- Envelope encoding/decoding ---
function envelopeRequest(operation) {
    const json = JSON.stringify(operation);
    const jsonBytes = Buffer.from(json, "utf-8");
    const plaintext = Buffer.alloc(ENVELOPE_PLAINTEXT_SIZE);
    plaintext.writeUInt32BE(jsonBytes.length, 0);
    jsonBytes.copy(plaintext, 4, 0, Math.min(jsonBytes.length, ENVELOPE_PLAINTEXT_SIZE - 4));
    const remaining = ENVELOPE_PLAINTEXT_SIZE - 4 - jsonBytes.length;
    if (remaining > 0) {
        randomBytes(remaining).copy(plaintext, 4 + jsonBytes.length);
    }
    return { data: plaintext.toString("hex") };
}
function parseEnvelope(hex) {
    const buf = Buffer.from(hex, "hex");
    const jsonLen = buf.readUInt32BE(0);
    const jsonStr = buf.subarray(4, 4 + jsonLen).toString("utf-8");
    return JSON.parse(jsonStr);
}
function padToken(token) {
    if (token.length >= DUMMY_TOKEN_LENGTH)
        return token.slice(0, DUMMY_TOKEN_LENGTH);
    return token + "x".repeat(DUMMY_TOKEN_LENGTH - token.length);
}
function generateDummyToken() {
    return randomBytes(DUMMY_TOKEN_LENGTH / 2).toString("hex");
}
//# sourceMappingURL=uniform-http-client.js.map