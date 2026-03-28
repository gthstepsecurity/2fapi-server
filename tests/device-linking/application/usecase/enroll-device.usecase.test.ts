// Copyright (c) 2025-2026 Continuum Identity SAS. All rights reserved.
// Licensed under the Business Source License 1.1. See LICENSE for details.
import { describe, it, expect } from "vitest";
import { EnrollDeviceUseCase } from "../../../../src/device-linking/application/usecase/enroll-device.usecase.js";
import { EnrollmentToken } from "../../../../src/device-linking/domain/model/enrollment-token.js";
import type { EnrollmentTokenStore } from "../../../../src/device-linking/domain/port/outgoing/enrollment-token-store.js";
import type { DeviceRegistrationStore } from "../../../../src/device-linking/domain/port/outgoing/device-registration-store.js";
import type { DeviceRegistration } from "../../../../src/device-linking/domain/model/device-registration.js";

const BASE_TIME = 1711540000000;
const ENROLLMENT_TTL_MS = 300_000; // 5 minutes

function createTokenStore(
  token: EnrollmentToken | null,
): EnrollmentTokenStore & { saved: EnrollmentToken[]; consumed: boolean } {
  let consumed = false;
  const saved: EnrollmentToken[] = [];
  return {
    saved,
    consumed,
    async save(t: EnrollmentToken) { saved.push(t); },
    async findByValue() { return token; },
    async atomicConsume(_value: string) {
      if (!token || consumed || token.consumed) return null;
      consumed = true;
      const consumedToken = token.consume();
      saved.push(consumedToken);
      return consumedToken;
    },
  };
}

function createDeviceStore(): DeviceRegistrationStore & { saved: DeviceRegistration[] } {
  const saved: DeviceRegistration[] = [];
  return {
    saved,
    async save(reg: DeviceRegistration) { saved.push(reg); },
    async findByClientId() { return []; },
    async findByDeviceId() { return null; },
    async markRevoked() {},
    async countActive() { return 0; },
  };
}

function validToken(): EnrollmentToken {
  return EnrollmentToken.create({
    value: "etok-abc",
    clientId: "alice",
    createdAt: BASE_TIME,
    ttlMs: ENROLLMENT_TTL_MS,
  });
}

describe("EnrollDeviceUseCase", () => {
  it("rejects invalid commitment and consumes token", async () => {
    const tokenStore = createTokenStore(validToken());
    const deviceStore = createDeviceStore();

    const useCase = new EnrollDeviceUseCase({
      enrollmentTokenStore: tokenStore,
      deviceRegistrationStore: deviceStore,
      validateCommitment: (_hex: string) => false,
      nowMs: () => BASE_TIME + 10_000,
      generateDeviceId: () => "dev-1",
    });

    const result = await useCase.execute({
      enrollmentToken: "etok-abc",
      commitmentHex: "0000000000",
      deviceName: "Firefox on Windows",
    });

    expect(result.status).toBe("invalid_commitment");
    expect(deviceStore.saved).toHaveLength(0);
    // Token is consumed atomically even on failure (single-use, RT-DL-06)
    expect(tokenStore.saved).toHaveLength(1); // atomicConsume saved it
    expect(tokenStore.saved[0]!.consumed).toBe(true);
  });

  it("enrolls device with valid commitment and token", async () => {
    const tokenStore = createTokenStore(validToken());
    const deviceStore = createDeviceStore();

    const useCase = new EnrollDeviceUseCase({
      enrollmentTokenStore: tokenStore,
      deviceRegistrationStore: deviceStore,
      validateCommitment: () => true,
      nowMs: () => BASE_TIME + 10_000,
      generateDeviceId: () => "dev-1",
    });

    const result = await useCase.execute({
      enrollmentToken: "etok-abc",
      commitmentHex: "aabbcc",
      deviceName: "Firefox on Windows",
    });

    expect(result.status).toBe("enrolled");
    if (result.status === "enrolled") {
      expect(result.deviceId).toBe("dev-1");
    }
    expect(deviceStore.saved).toHaveLength(1);
    expect(deviceStore.saved[0]!.commitmentHex).toBe("aabbcc");
    expect(deviceStore.saved[0]!.deviceName).toBe("Firefox on Windows");
  });

  it("rejects expired enrollment token", async () => {
    const tokenStore = createTokenStore(validToken());
    const deviceStore = createDeviceStore();

    const useCase = new EnrollDeviceUseCase({
      enrollmentTokenStore: tokenStore,
      deviceRegistrationStore: deviceStore,
      validateCommitment: () => true,
      nowMs: () => BASE_TIME + ENROLLMENT_TTL_MS + 1,
      generateDeviceId: () => "dev-1",
    });

    const result = await useCase.execute({
      enrollmentToken: "etok-abc",
      commitmentHex: "aabbcc",
      deviceName: "Firefox on Windows",
    });

    expect(result.status).toBe("token_expired");
    expect(deviceStore.saved).toHaveLength(0);
  });

  it("rejects unknown enrollment token", async () => {
    const tokenStore = createTokenStore(null);
    const deviceStore = createDeviceStore();

    const useCase = new EnrollDeviceUseCase({
      enrollmentTokenStore: tokenStore,
      deviceRegistrationStore: deviceStore,
      validateCommitment: () => true,
      nowMs: () => BASE_TIME,
      generateDeviceId: () => "dev-1",
    });

    const result = await useCase.execute({
      enrollmentToken: "unknown",
      commitmentHex: "aabbcc",
      deviceName: "Firefox on Windows",
    });

    expect(result.status).toBe("invalid_token");
  });
});
