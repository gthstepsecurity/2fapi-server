// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import { DevicePassword } from "../../domain/model/device-password.js";
import { VaultEntry } from "../../domain/model/vault-entry.js";
import type { CryptoEngine } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type {
  SealVaultRequest,
  SealVaultResponse,
  SealVaultError,
} from "../../domain/port/incoming/seal-vault.js";

const DEFAULT_TTL_HOURS = 72;
const VAULT_VERSION = 2;

/**
 * Seals a vault using the OPRF protocol (Tier 1a).
 * 1. Validate password
 * 2. Server generates OPRF key (client never sees it)
 * 3. Client blinds password → server evaluates → client unblinds → HKDF → vault key
 * 4. AES-256-GCM encrypt(secret || blinding) → localStorage
 */
export class SealVaultOprfUseCase {
  constructor(
    private readonly crypto: CryptoEngine,
    private readonly oprfGateway: OprfGateway,
    private readonly localStore: VaultLocalStore,
  ) {}

  async execute(request: SealVaultRequest): Promise<Result<SealVaultResponse, SealVaultError>> {
    // 1. Validate password
    const passwordResult = DevicePassword.create(request.password);
    if (passwordResult.isErr()) {
      return err("PASSWORD_TOO_SHORT");
    }
    const password = passwordResult.unwrap();
    if (!password.matches(request.passwordConfirmation)) {
      return err("PASSWORDS_DO_NOT_MATCH");
    }

    // 2. OPRF: blind the password
    const { blindedPoint, blindingFactor } = this.crypto.oprfBlind(password.value);

    // 3. Send blinded point to server for OPRF evaluation
    let evaluated: Uint8Array;
    let deviceId: string;
    try {
      const response = await this.oprfGateway.requestEvaluation({
        clientId: request.clientId,
        deviceId: request.deviceId,
        blindedPoint,
      });
      if (response.status === "wiped") {
        return err("SERVER_UNREACHABLE");
      }
      evaluated = response.evaluated;
      deviceId = request.deviceId;
    } catch {
      return err("SERVER_UNREACHABLE");
    }

    // 4. Unblind → OPRF output U
    const oprfOutput = this.crypto.oprfUnblind(evaluated, blindingFactor);

    // R5-04 FIX: zeroize blinding factor immediately after unblind
    this.crypto.zeroize(blindingFactor);

    // 5. Derive vault key from OPRF output
    const vaultKey = await this.crypto.deriveVaultKeyFromOprf(oprfOutput, deviceId);

    // 6. Zeroize OPRF output
    this.crypto.zeroize(oprfOutput);

    try {
      // 7. Encrypt the secret material
      const plaintext = new Uint8Array(64);
      plaintext.set(request.secret, 0);
      plaintext.set(request.blinding, 32);

      const encrypted = await this.crypto.encrypt(vaultKey, plaintext);

      // 8. Zeroize
      this.crypto.zeroize(vaultKey);
      this.crypto.zeroize(plaintext);

      // 9. Store encrypted vault locally
      const entry = VaultEntry.create({
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
        deviceId,
        createdAtMs: Date.now(),
        maxTtlHours: DEFAULT_TTL_HOURS,
        version: VAULT_VERSION,
      });

      this.localStore.save(request.email, entry);
      return ok({ deviceId });
    } catch {
      this.crypto.zeroize(vaultKey);
      return err("CRYPTO_UNAVAILABLE");
    }
  }
}
