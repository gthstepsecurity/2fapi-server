import { randomBytes } from "node:crypto";
import { ClientId } from "../../../domain/model/client-id.js";
export class CryptoRandomIdGenerator {
    generate() {
        // Note: the intermediate Buffer from randomBytes is not zeroed after copy.
        // This is acceptable for opaque identifiers (not secrets).
        // For secret material, use buf.fill(0) after copying to Uint8Array.
        const bytes = randomBytes(16);
        return ClientId.fromBytes(new Uint8Array(bytes));
    }
}
//# sourceMappingURL=crypto-random-id-generator.js.map