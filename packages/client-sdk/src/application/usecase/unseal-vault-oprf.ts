// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import type { CryptoEngine, DerivedSecret } from "../../domain/port/outgoing/crypto-engine.js";
import type { OprfGateway } from "../../domain/port/outgoing/oprf-gateway.js";
import type { VaultLocalStore } from "../../domain/port/outgoing/vault-local-store.js";
import type {
  UnsealVaultRequest,
  UnsealVaultResponse,
  UnsealVaultError,
  UnsealVaultFailureDetail,
} from "../../domain/port/incoming/unseal-vault.js";

/**
 * Unseals a vault using the OPRF protocol (Tier 1a — 2-factor: password + server OPRF).
 * The server never sees the password. The client never sees the OPRF key.
 */
export class UnsealVaultOprfUseCase {
  /** Detail of the last error (available after a failed execute call). */
  lastErrorDetail: UnsealVaultFailureDetail | null = null;

  constructor(
    private readonly crypto: CryptoEngine,
    private readonly oprfGateway: OprfGateway,
    private readonly localStore: VaultLocalStore,
  ) {}

  async execute(request: UnsealVaultRequest): Promise<Result<UnsealVaultResponse, UnsealVaultError>> {
    this.lastErrorDetail = null;
    const entry = this.localStore.load(request.email);
    if (!entry) {
      return err("NO_VAULT_FOUND");
    }

    if (entry.isExpired(Date.now())) {
      this.localStore.delete(request.email);
      return err("VAULT_EXPIRED");
    }

    // R8-02 FIX: reject legacy vault versions (pre-OPRF)
    if (entry.version < 2) {
      this.localStore.delete(request.email);
      return err("VAULT_CORRUPTED");
    }

    // OPRF: blind the password, send to server
    const { blindedPoint, blindingFactor } = this.crypto.oprfBlind(request.password);

    let response;
    try {
      response = await this.oprfGateway.requestEvaluation({
        clientId: request.clientId,
        deviceId: entry.deviceId,
        blindedPoint,
      });
    } catch {
      return err("SERVER_UNREACHABLE");
    }

    if (response.status === "wiped") {
      this.localStore.delete(request.email);
      return err("VAULT_WIPED");
    }

    // Unblind server evaluation → OPRF output U
    const oprfOutput = this.crypto.oprfUnblind(response.evaluated, blindingFactor);

    // R2-02 FIX: zeroize blinding factor immediately after unblind
    this.crypto.zeroize(blindingFactor);

    // Derive vault key from OPRF output via HKDF
    const vaultKey = await this.crypto.deriveVaultKeyFromOprf(oprfOutput, entry.deviceId);

    // Zeroize OPRF output immediately after key derivation
    this.crypto.zeroize(oprfOutput);

    // Decrypt vault
    try {
      const decrypted = await this.crypto.decrypt(vaultKey, {
        iv: entry.iv,
        ciphertext: entry.ciphertext,
        tag: entry.tag,
      });

      const secret: DerivedSecret = {
        secret: decrypted.slice(0, 32),
        blinding: decrypted.slice(32, 64),
      };

      // Zeroize plaintext after extraction
      this.crypto.zeroize(decrypted);

      return ok({ secret, attemptsRemaining: response.attemptsRemaining });
    } catch {
      await this.oprfGateway.reportFailure(request.clientId, entry.deviceId).catch(() => {});
      this.lastErrorDetail = { error: "WRONG_PASSWORD", attemptsRemaining: response.attemptsRemaining };
      return err("WRONG_PASSWORD");
    } finally {
      // Always zeroize vault key
      this.crypto.zeroize(vaultKey);
    }
  }
}
