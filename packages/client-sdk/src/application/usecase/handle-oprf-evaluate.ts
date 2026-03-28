// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { type Result, ok, err } from "../../domain/model/result.js";
import { OprfKey } from "../../domain/model/oprf-key.js";
import { VaultAttemptCounter } from "../../domain/model/vault-attempt-counter.js";
import type { OprfKeyStore } from "../../domain/port/outgoing/oprf-key-store.js";
import type { VaultAttemptStore } from "../../domain/port/outgoing/vault-attempt-store.js";
import type { OprfNativeEvaluator } from "../../domain/port/outgoing/oprf-native-evaluator.js";
import { StubOprfEvaluator } from "../../domain/port/outgoing/oprf-native-evaluator.js";

const BLINDED_POINT_LENGTH = 32;

interface DeviceIdentifier {
  readonly clientId: string;
  readonly deviceId: string;
}

interface EvaluateRequest extends DeviceIdentifier {
  readonly blindedPoint: Uint8Array;
}

export type EvaluateResponse =
  | { readonly status: "allowed"; readonly evaluated: Uint8Array; readonly attemptsRemaining: number }
  | { readonly status: "wiped" };

export type EvaluateError =
  | "INVALID_BLINDED_ELEMENT"
  | "NO_VAULT_REGISTERED";

interface SealResponse {
  readonly status: "ready";
  readonly deviceId: string;
}

/**
 * Server-side use case: OPRF evaluation.
 *
 * R2-01 FIX: The scalar multiplication E = k · B is performed by an
 * injected OprfNativeEvaluator (port pattern):
 *   - Production: NapiOprfEvaluator (Rust crypto-core via napi-rs)
 *   - Browser: WasmOprfEvaluator (Rust crypto-core via wasm-bindgen)
 *   - Tests: StubOprfEvaluator (XOR, domain-level only, BLOCKED in production)
 *
 * The XOR simulation is no longer embedded in this use case.
 */
export class HandleOprfEvaluateUseCase {
  private readonly evaluator: OprfNativeEvaluator;

  constructor(
    private readonly keyStore: OprfKeyStore,
    private readonly attemptStore: VaultAttemptStore,
    evaluator?: OprfNativeEvaluator,
  ) {
    this.evaluator = evaluator ?? new StubOprfEvaluator();
  }

  async evaluate(request: EvaluateRequest): Promise<Result<EvaluateResponse, EvaluateError>> {
    // 1. Validate blinded point format
    if (request.blindedPoint.length !== BLINDED_POINT_LENGTH) {
      return err("INVALID_BLINDED_ELEMENT");
    }
    if (request.blindedPoint.every(b => b === 0)) {
      return err("INVALID_BLINDED_ELEMENT");
    }

    // 2. Check counter for wipe
    const counter = await this.attemptStore.findByDevice(request.clientId, request.deviceId);
    if (counter?.isWiped) {
      await this.keyStore.delete(request.clientId, request.deviceId);
      return ok({ status: "wiped" });
    }

    // 3. Retrieve OPRF key
    const key = await this.keyStore.findByDevice(request.clientId, request.deviceId);
    if (!key) {
      return err("NO_VAULT_REGISTERED");
    }

    // 4. Initialize counter
    let currentCounter = counter ?? VaultAttemptCounter.create(request.clientId, request.deviceId);
    if (!counter) {
      await this.attemptStore.save(currentCounter);
    }

    // 5. Evaluate E = k · B via injected native evaluator (R2-01 FIX)
    const oprfKeyBytes = key.valueForEvaluation();
    const evaluated = this.evaluator.evaluate(request.blindedPoint, oprfKeyBytes);

    return ok({
      status: "allowed",
      evaluated,
      attemptsRemaining: currentCounter.attemptsRemaining,
    });
  }

  async seal(params: DeviceIdentifier): Promise<Result<SealResponse, string>> {
    const key = OprfKey.generate(params.clientId, params.deviceId);
    await this.keyStore.save(key);

    const counter = VaultAttemptCounter.create(params.clientId, params.deviceId);
    await this.attemptStore.save(counter);

    return ok({ status: "ready", deviceId: params.deviceId });
  }

  async reportFailure(params: DeviceIdentifier): Promise<void> {
    let counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
    if (!counter) {
      counter = VaultAttemptCounter.create(params.clientId, params.deviceId);
    }

    const updated = counter.recordFailure();
    await this.attemptStore.save(updated);

    if (updated.isWiped) {
      await this.keyStore.delete(params.clientId, params.deviceId);
    }
  }

  async reportSuccess(params: DeviceIdentifier): Promise<void> {
    const counter = await this.attemptStore.findByDevice(params.clientId, params.deviceId);
    if (!counter) return;

    const reset = counter.recordSuccess();
    await this.attemptStore.save(reset);
  }
}
