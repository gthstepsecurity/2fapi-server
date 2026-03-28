// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import type { CryptoEngine, DerivedSecret } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type { HardwareKeyStore } from "../../domain/port/outgoing/hardware-key-store.js";
import type {
  UnsealVaultRequest,
  UnsealVaultResponse,
  UnsealVaultError,
} from "../../domain/port/incoming/unseal-vault.js";

/**
 * Unseals a vault using 3 factors: password + OPRF + hardware (Tier 1b).
 * vault_key = HKDF(OPRF_output || hardware_key, device_id)
 *
 * Falls back to 2-factor (Tier 1a) if hardware PRF is unavailable.
 */
export class UnsealVaultOprf3FactorUseCase {
  constructor(
    private readonly crypto: CryptoEngine,
    private readonly oprfGateway: OprfGateway,
    private readonly localStore: VaultLocalStore,
    private readonly hardwareKeyStore: HardwareKeyStore,
  ) {}

  async execute(request: UnsealVaultRequest & { rpId?: string }): Promise<Result<UnsealVaultResponse, UnsealVaultError>> {
    const entry = this.localStore.load(request.email);
    if (!entry) return err("NO_VAULT_FOUND");

    if (entry.isExpired(Date.now())) {
      this.localStore.delete(request.email);
      return err("VAULT_EXPIRED");
    }

    // Factor 1+2: OPRF (password + server key)
    const { blindedPoint, blindingFactor } = this.crypto.oprfBlind(request.password);

    let oprfResponse;
    try {
      oprfResponse = await this.oprfGateway.requestEvaluation({
        clientId: request.clientId,
        deviceId: entry.deviceId,
        blindedPoint,
      });
    } catch {
      return err("SERVER_UNREACHABLE");
    }

    if (oprfResponse.status === "wiped") {
      this.localStore.delete(request.email);
      return err("VAULT_WIPED");
    }

    const oprfOutput = this.crypto.oprfUnblind(oprfResponse.evaluated, blindingFactor);

    // R2-02 FIX: zeroize blinding factor immediately after unblind
    this.crypto.zeroize(blindingFactor);

    // Factor 3: Hardware key (optional — falls back to 2-factor)
    let ikm: Uint8Array;
    const prfSupported = await this.hardwareKeyStore.isPrfSupported();

    if (prfSupported && request.rpId) {
      const hwResult = await this.hardwareKeyStore.deriveKey({
        email: request.email,
        rpId: request.rpId,
        salt: "2fapi-vault-hw-v1",
      });

      if (hwResult.status === "ok") {
        // 3-factor: OPRF output || hardware key
        ikm = new Uint8Array(64);
        ikm.set(oprfOutput, 0);
        ikm.set(hwResult.hwKey, 32);
        this.crypto.zeroize(oprfOutput);
      } else {
        // PRF failed — fall back to 2-factor
        ikm = oprfOutput;
      }
    } else {
      // No PRF — 2-factor only
      ikm = oprfOutput;
    }

    const vaultKey = await this.crypto.deriveVaultKeyFromOprf(ikm, entry.deviceId);
    this.crypto.zeroize(ikm);

    try {
      const decrypted = await this.crypto.decrypt(vaultKey, {
        iv: entry.iv, ciphertext: entry.ciphertext, tag: entry.tag,
      });

      const secret: DerivedSecret = {
        secret: decrypted.slice(0, 32),
        blinding: decrypted.slice(32, 64),
      };
      this.crypto.zeroize(decrypted);

      return ok({ secret, attemptsRemaining: oprfResponse.attemptsRemaining });
    } catch {
      await this.oprfGateway.reportFailure(request.clientId, entry.deviceId).catch(() => {});
      return err("WRONG_PASSWORD");
    } finally {
      this.crypto.zeroize(vaultKey);
    }
  }
}
